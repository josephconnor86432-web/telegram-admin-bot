import os
import time
import hmac
import html
import logging
from functools import wraps
from contextlib import contextmanager

import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify
import telebot
from telebot import types

# ---------------------------------------------------------
# تنظیمات و متغیرهای محیطی
# ---------------------------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BOT_TOKEN = os.environ['BOT_TOKEN']
SUPER_ADMIN_ID = int(os.environ['SUPER_ADMIN_ID'])
DATABASE_URL = os.environ['DATABASE_URL']
PANEL_PASSWORD = os.environ.get('PANEL_PASSWORD', 'admin123')
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())
CRON_SECRET = os.environ.get('CRON_SECRET', 'cron_secure_token')

# تنظیمات پیش‌فرض ضد خرابکاری (Anti-Raid Defaults)
DEFAULT_MASS_BAN_THRESHOLD = 5         # تعداد بن مجاز در بازه زمانی
DEFAULT_MASS_RESTRICT_THRESHOLD = 8    # تعداد محدودسازی مجاز
DEFAULT_WINDOW_MINUTES = 5             # بازه زمانی (دقیقه)
DEFAULT_INACTIVITY_DAYS = 30           # آستانه خواب مالک (روز)

WARNING_MESSAGE = """⚠️ <b>هشدار امنیتی ربات نظارت:</b>
مالک این گروه برای مدت طولانی هیچ فعالیتی نداشته است.
در صورتی که مالک ظرف ۲۴ ساعت آینده پیامی در گروه ارسال نکند، تمامی ادمین‌های غیرمحافظت‌شده به منظور حفظ امنیت گروه عزل خواهند شد."""

bot = telebot.TeleBot(BOT_TOKEN, threaded=False, parse_mode='HTML')
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# ---------------------------------------------------------
# اتصال پایگاه داده و Connection Pool
# ---------------------------------------------------------
db_pool = ThreadedConnectionPool(1, 20, DATABASE_URL, sslmode='require')

@contextmanager
def get_db():
    conn = db_pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"Database Error: {e}")
        raise
    finally:
        db_pool.putconn(conn)

def init_db():
    """ساخت خودکار جداول دیتابیس در صورت عدم وجود"""
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                chat_id BIGINT PRIMARY KEY,
                chat_title TEXT NOT NULL,
                owner_id BIGINT NOT NULL,
                threshold_days INT DEFAULT 30,
                last_owner_activity BIGINT NOT NULL,
                chat_type TEXT,
                strict_promote_lock BOOLEAN DEFAULT TRUE,
                ban_threshold INT DEFAULT 5,
                restrict_threshold INT DEFAULT 8,
                window_minutes INT DEFAULT 5,
                created_at BIGINT
            );

            CREATE TABLE IF NOT EXISTS protected_admins (
                chat_id BIGINT,
                admin_id BIGINT,
                added_at BIGINT,
                PRIMARY KEY (chat_id, admin_id)
            );

            CREATE TABLE IF NOT EXISTS action_log (
                id SERIAL PRIMARY KEY,
                chat_id BIGINT,
                action TEXT,
                actor_id BIGINT,
                target_id BIGINT,
                details TEXT,
                timestamp BIGINT
            );

            CREATE TABLE IF NOT EXISTS admin_actions (
                id SERIAL PRIMARY KEY,
                chat_id BIGINT,
                admin_id BIGINT,
                action_type TEXT,
                target_id BIGINT,
                timestamp BIGINT
            );

            CREATE TABLE IF NOT EXISTS flags (
                id SERIAL PRIMARY KEY,
                chat_id BIGINT,
                admin_id BIGINT,
                reason TEXT,
                reported_by BIGINT,
                status TEXT DEFAULT 'pending',
                timestamp BIGINT
            );

            CREATE TABLE IF NOT EXISTS pending_warnings (
                chat_id BIGINT PRIMARY KEY,
                warned_at BIGINT
            );
            """)

init_db()

# ---------------------------------------------------------
# توابع کار با دیتابیس
# ---------------------------------------------------------
def add_or_update_group(chat_id, title, owner_id, chat_type, threshold=30):
    now = int(time.time())
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO groups (chat_id, chat_title, owner_id, threshold_days, last_owner_activity, chat_type, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (chat_id) DO UPDATE 
                SET chat_title = EXCLUDED.chat_title,
                    owner_id = EXCLUDED.owner_id,
                    chat_type = EXCLUDED.chat_type;
            """, (chat_id, title, owner_id, threshold, now, chat_type, now))

def update_owner_activity(chat_id, ts):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("UPDATE groups SET last_owner_activity=%s WHERE chat_id=%s", (ts, chat_id))

def get_group(chat_id):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("SELECT chat_id, chat_title, owner_id, threshold_days, last_owner_activity, chat_type, strict_promote_lock, ban_threshold, restrict_threshold, window_minutes FROM groups WHERE chat_id=%s", (chat_id,))
            return c.fetchone()

def get_all_groups():
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("SELECT chat_id, chat_title, owner_id, threshold_days, last_owner_activity, chat_type, strict_promote_lock FROM groups ORDER BY chat_id")
            return c.fetchall()

def update_group_settings(chat_id, threshold_days, strict_promote_lock, ban_threshold, restrict_threshold, window_minutes):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("""
                UPDATE groups 
                SET threshold_days=%s, strict_promote_lock=%s, ban_threshold=%s, restrict_threshold=%s, window_minutes=%s 
                WHERE chat_id=%s
            """, (threshold_days, strict_promote_lock, ban_threshold, restrict_threshold, window_minutes, chat_id))

def add_protected_admin(chat_id, admin_id):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("INSERT INTO protected_admins (chat_id, admin_id, added_at) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                      (chat_id, admin_id, int(time.time())))

def remove_protected_admin(chat_id, admin_id):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("DELETE FROM protected_admins WHERE chat_id=%s AND admin_id=%s", (chat_id, admin_id))

def get_protected_admins(chat_id):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("SELECT admin_id FROM protected_admins WHERE chat_id=%s", (chat_id,))
            return [r[0] for r in c.fetchall()]

def log_action(chat_id, action, actor_id, target_id, details=""):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO action_log (chat_id, action, actor_id, target_id, details, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (chat_id, action, actor_id, target_id, details, int(time.time())))

def get_action_log(chat_id, limit=40):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("""
                SELECT action, actor_id, target_id, details, timestamp 
                FROM action_log WHERE chat_id=%s ORDER BY timestamp DESC LIMIT %s
            """, (chat_id, limit))
            return c.fetchall()

def log_admin_action(chat_id, admin_id, action_type, target_id):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO admin_actions (chat_id, admin_id, action_type, target_id, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            """, (chat_id, admin_id, action_type, target_id, int(time.time())))

def count_recent_actions(chat_id, admin_id, action_type, window_minutes):
    since = int(time.time()) - (window_minutes * 60)
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("""
                SELECT COUNT(*) FROM admin_actions
                WHERE chat_id=%s AND admin_id=%s AND action_type=%s AND timestamp>=%s
            """, (chat_id, admin_id, action_type, since))
            return c.fetchone()[0]

def add_flag(chat_id, admin_id, reason, reported_by):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO flags (chat_id, admin_id, reason, reported_by, timestamp)
                VALUES (%s, %s, %s, %s, %s) RETURNING id
            """, (chat_id, admin_id, reason, reported_by, int(time.time())))
            return c.fetchone()[0]

def get_flags(status='pending'):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("SELECT id, chat_id, admin_id, reason, reported_by, status, timestamp FROM flags WHERE status=%s ORDER BY timestamp DESC", (status,))
            return c.fetchall()

def get_flag(flag_id):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("SELECT id, chat_id, admin_id, reason, reported_by, status, timestamp FROM flags WHERE id=%s", (flag_id,))
            return c.fetchone()

def resolve_flag(flag_id, status='resolved'):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("UPDATE flags SET status=%s WHERE id=%s", (status, flag_id))

def get_pending_warning(chat_id):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("SELECT warned_at FROM pending_warnings WHERE chat_id=%s", (chat_id,))
            row = c.fetchone()
            return row[0] if row else None

def set_pending_warning(chat_id, ts):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO pending_warnings (chat_id, warned_at) VALUES (%s, %s)
                ON CONFLICT (chat_id) DO UPDATE SET warned_at=%s
            """, (chat_id, ts, ts))

def clear_pending_warning(chat_id):
    with get_db() as conn:
        with conn.cursor() as c:
            c.execute("DELETE FROM pending_warnings WHERE chat_id=%s", (chat_id,))

# ---------------------------------------------------------
# توابع مدیریتی ربات تلگرام
# ---------------------------------------------------------
def get_group_owner(chat_id):
    """یافتن مالک اصلی و سازنده گروه به صورت داینامیک از تلگرام"""
    try:
        admins = bot.get_chat_administrators(chat_id)
        for a in admins:
            if a.status == 'creator':
                return a.user.id
    except Exception as e:
        logging.error(f"Error finding creator for {chat_id}: {e}")
    return None

def demote_admin(chat_id, admin_id):
    """خلع ید و سلب تمام دسترسی‌های مدیریتی یک ادمین در تلگرام"""
    try:
        bot.promote_chat_member(
            chat_id, admin_id,
            can_change_info=False,
            can_post_messages=False,
            can_edit_messages=False,
            can_delete_messages=False,
            can_invite_users=False,
            can_restrict_members=False,
            can_pin_messages=False,
            can_promote_members=False,
            can_manage_video_chats=False,
            can_manage_chat=False,
            can_manage_topics=False,
            can_post_stories=False,
            can_edit_stories=False,
            can_delete_stories=False
        )
        return True
    except Exception as e:
        logging.error(f"Failed to demote {admin_id} in {chat_id}: {e}")
        # در صورت شکست، روش جایگزین کیک و آن‌بن کردن برای حذف کامل از لیست ادمین‌ها
        try:
            bot.ban_chat_member(chat_id, admin_id)
            bot.unban_chat_member(chat_id, admin_id)
            return True
        except Exception as e2:
            logging.error(f"Fallback kick also failed: {e2}")
            return False

def notify_super_admin(chat_id, admin_id, group_title, reason, flag_id, auto_demoted=False):
    """ارسال اعلان آنی و فوری به سوپر ادمین"""
    try:
        info = bot.get_chat_member(chat_id, admin_id).user
        name = info.first_name or "نامشخص"
        username = f"@{info.username}" if info.username else "ندارد"
    except Exception:
        name = "ناشناس"
        username = "ندارد"

    status_str = "🔴 <b>ادمین به صورت خودکار عزل شد!</b>" if auto_demoted else "⚠️ <b>نیاز به اقدام سوپرادمین:</b>"

    text = (
        f"🚨 <b>هشدار امنیتی در گروه!</b>\n\n"
        f"{status_str}\n"
        f"📍 <b>گروه:</b> {html.escape(str(group_title))}\n"
        f"👤 <b>ادمین:</b> {html.escape(name)} ({username})\n"
        f"🆔 <b>آیدی عددی:</b> <code>{admin_id}</code>\n"
        f"💬 <b>علت گزارش:</b> {html.escape(reason)}\n"
        f"⏰ <b>زمان:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )

    markup = types.InlineKeyboardMarkup(row_width=2)
    if not auto_demoted:
        markup.add(
            types.InlineKeyboardButton("🔴 عزل فوری ادمین", callback_data=f"rem_{chat_id}_{admin_id}_{flag_id}"),
            types.InlineKeyboardButton("✅ نادیده گرفتن", callback_data=f"ign_{flag_id}")
        )
    else:
        markup.add(
            types.InlineKeyboardButton("🛡 افزودن به لیست مصون", callback_data=f"protect_{chat_id}_{admin_id}_{flag_id}"),
            types.InlineKeyboardButton("✅ تأیید", callback_data=f"ign_{flag_id}")
        )

    try:
        bot.send_message(SUPER_ADMIN_ID, text, reply_markup=markup)
    except Exception as e:
        logging.error(f"Error notifying super admin: {e}")

# ---------------------------------------------------------
# هندلرهای ربات تلگرام
# ---------------------------------------------------------
@bot.message_handler(commands=['start', 'help'])
def cmd_start(message):
    text = (
        "🤖 <b>ربات پیشرفته مدیریت و حفاظت از ادمین‌های گروه</b>\n\n"
        "<b>دستورات مدیر کل:</b>\n"
        "▫️ <code>/register</code> - ثبت گروه و شناسایی خودکار مالک\n"
        "▫️ <code>/protect_admin &lt;ID&gt;</code> - افزودن ادمین به لیست سفید (مصون از حذف)\n"
        "▫️ <code>/unprotect_admin &lt;ID&gt;</code> - حذف از لیست سفید\n"
        "▫️ <code>/remove_admin &lt;ID&gt;</code> - عزل فوری یک ادمین\n"
        "▫️ <code>/set_threshold &lt;Days&gt;</code> - تنظیم روزهای خواب مجاز مالک\n"
        "▫️ <code>/status</code> - وضعیت امنیتی و ادمین‌های گروه\n\n"
        "<b>دستورات عمومی:</b>\n"
        "▫️ <code>/report_admin &lt;علت&gt;</code> (ریپلای روی پیام ادمین خاطی)"
    )
    bot.reply_to(message, text)

@bot.message_handler(commands=['register'])
def register_group(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        bot.reply_to(message, "❌ دسترسی غیرمجاز.")
        return
    chat = message.chat
    if chat.type not in ['group', 'supergroup']:
        bot.reply_to(message, "❌ این دستور فقط داخل گروه‌ها کار می‌کند.")
        return

    try:
        bm = bot.get_chat_member(chat.id, bot.get_me().id)
        if bm.status != 'administrator' or not bm.can_promote_members or not bm.can_restrict_members:
            bot.reply_to(message, "❌ ربات باید ادمین با دسترسی کامل (Promote/Restrict) باشد.")
            return
    except Exception as e:
        bot.reply_to(message, f"خطا در بررسی دسترسی‌های ربات: {e}")
        return

    owner_id = get_group_owner(chat.id)
    if not owner_id:
        owner_id = SUPER_ADMIN_ID  # در صورت عدم تشخیص، موقتاً سوپرادمین
        owner_note = "\n⚠️ مالک اصلی یافت نشد؛ سوپرادمین موقتاً ثبت شد."
    else:
        owner_note = f"\n👑 مالک گروه: <code>{owner_id}</code>"

    add_or_update_group(chat.id, chat.title, owner_id, chat.type)
    bot.reply_to(message, f"✅ گروه <b>{html.escape(chat.title)}</b> با موفقیت ثبت شد.{owner_note}")

@bot.message_handler(commands=['protect_admin'])
def cmd_protect_admin(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    try:
        parts = message.text.split()
        target_id = int(parts[1]) if len(parts) > 1 else (message.reply_to_message.from_user.id if message.reply_to_message else None)
        if not target_id:
            raise ValueError()
        add_protected_admin(message.chat.id, target_id)
        bot.reply_to(message, f"🛡 ادمین <code>{target_id}</code> به لیست سفید و محافظت‌شده اضافه شد.")
    except Exception:
        bot.reply_to(message, "راهنما: <code>/protect_admin USER_ID</code> یا ریپلای روی پیام ادمین.")

@bot.message_handler(commands=['unprotect_admin'])
def cmd_unprotect_admin(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    try:
        parts = message.text.split()
        target_id = int(parts[1]) if len(parts) > 1 else (message.reply_to_message.from_user.id if message.reply_to_message else None)
        if not target_id:
            raise ValueError()
        remove_protected_admin(message.chat.id, target_id)
        bot.reply_to(message, f"⚠️ ادمین <code>{target_id}</code> از لیست محافظت‌شده خارج شد.")
    except Exception:
        bot.reply_to(message, "راهنما: <code>/unprotect_admin USER_ID</code>")

@bot.message_handler(commands=['set_threshold'])
def cmd_set_threshold(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    try:
        days = int(message.text.split()[1])
        group = get_group(message.chat.id)
        if not group:
            bot.reply_to(message, "❌ ابتدا گروه را با /register ثبت کنید.")
            return
        update_group_settings(message.chat.id, days, group[6], group[7], group[8], group[9])
        bot.reply_to(message, f"✅ آستانه خواب مالک به <b>{days} روز</b> تنظیم شد.")
    except Exception:
        bot.reply_to(message, "راهنما: <code>/set_threshold 30</code>")

@bot.message_handler(commands=['remove_admin'])
def cmd_remove_admin(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    target_id = None
    if message.reply_to_message:
        target_id = message.reply_to_message.from_user.id
    else:
        try:
            target_id = int(message.text.split()[1])
        except Exception:
            bot.reply_to(message, "روی پیام ادمین ریپلای کنید یا: <code>/remove_admin USER_ID</code>")
            return
    if demote_admin(message.chat.id, target_id):
        log_action(message.chat.id, 'manual_demote', message.from_user.id, target_id, "عزل دستی توسط سوپر ادمین")
        bot.reply_to(message, f"✅ دسترسی‌های ادمین <code>{target_id}</code> سلب شد.")
    else:
        bot.reply_to(message, "❌ خطا در عزل ادمین. دسترسی‌های ربات را بررسی کنید.")

@bot.message_handler(commands=['status'])
def cmd_status(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    group = get_group(message.chat.id)
    if not group:
        bot.reply_to(message, "گروه در سیستم ثبت نشده است. از /register استفاده کنید.")
        return
    
    protected = get_protected_admins(message.chat.id)
    now = int(time.time())
    days_inactive = int((now - group[4]) / 86400)
    
    text = (
        f"📊 <b>وضعیت گروه: {html.escape(group[1])}</b>\n\n"
        f"👑 <b>مالک:</b> <code>{group[2]}</code>\n"
        f"⏳ <b>آخرین فعالیت مالک:</b> {days_inactive} روز پیش (آستانه: {group[3]} روز)\n"
        f"🔒 <b>قفل ارتقای ادمین:</b> {'فعال ✅' if group[6] else 'غیرفعال ❌'}\n"
        f"⚡ <b>محدودیت بن/میوت:</b> {group[7]} بن در {group[9]} دقیقه\n"
        f"🛡 <b>تعداد ادمین‌های مصون:</b> {len(protected)} نفر"
    )
    bot.reply_to(message, text)

@bot.message_handler(commands=['report_admin'])
def cmd_report_admin(message):
    if not message.reply_to_message:
        bot.reply_to(message, "❌ این دستور را روی پیام ادمین خاطی ریپلای کنید.")
        return
    target = message.reply_to_message.from_user
    if target.is_bot:
        bot.reply_to(message, "❌ امکان گزارش ربات‌ها وجود ندارد.")
        return

    admins = bot.get_chat_administrators(message.chat.id)
    if target.id not in [a.user.id for a in admins]:
        bot.reply_to(message, "❌ کاربر موردنظر در حال حاضر ادمین نیست.")
        return

    reason = "گزارش ارسال‌شده توسط اعضا"
    if len(message.text.split()) > 1:
        reason = message.text.split(maxsplit=1)[1]

    group = get_group(message.chat.id)
    title = group[1] if group else message.chat.title
    flag_id = add_flag(message.chat.id, target.id, reason, message.from_user.id)
    notify_super_admin(message.chat.id, target.id, title, reason, flag_id, auto_demoted=False)
    bot.reply_to(message, "✅ گزارش شما ثبت شد و برای سوپرادمین ارسال گردید.")

# ---------------------------------------------------------
# ردگیری فعالیت مالک و اعضا
# ---------------------------------------------------------
@bot.message_handler(func=lambda m: True, content_types=['text', 'photo', 'video', 'sticker', 'document', 'voice', 'audio', 'location'])
def track_owner_activity(message):
    group = get_group(message.chat.id)
    if not group:
        return
    owner_id = group[2]
    # اگر پیام از طرف مالک گروه یا کانال متصل باشد
    if message.from_user and message.from_user.id == owner_id:
        update_owner_activity(message.chat.id, int(time.time()))
        if get_pending_warning(message.chat.id):
            clear_pending_warning(message.chat.id)
            bot.send_message(message.chat.id, "✅ <b>فعالیت مالک گروه تأیید شد.</b> عملیات تعلیق و خلع ادمین‌ها لغو شد.")

# ---------------------------------------------------------
# رصد تغییرات و رفتارهای مشکوک ادمین‌ها (Anti-Raid Core)
# ---------------------------------------------------------
@bot.chat_member_handler()
def on_chat_member_update(update: types.ChatMemberUpdated):
    chat_id = update.chat.id
    group = get_group(chat_id)
    if not group:
        return

    actor = update.from_user
    old_status = update.old_chat_member.status
    new_status = update.new_chat_member.status
    target = update.new_chat_member.user

    # چشم‌پوشی از اقداماتی که کاربر روی خودش انجام داده (مثل لفت دادن)
    if actor.id == target.id:
        return

    owner_id = group[2]
    strict_lock = group[6]
    ban_thresh = group[7]
    restrict_thresh = group[8]
    window_min = group[9]

    # ادمین‌های مصون + مالک + سوپرادمین
    whitelist = get_protected_admins(chat_id) + [owner_id, SUPER_ADMIN_ID, bot.get_me().id]

    # 1. بن کردن / اخراج کاربر (Ban Detection)
    if new_status in ['kicked', 'banned'] and old_status not in ['kicked', 'banned']:
        log_admin_action(chat_id, actor.id, 'ban', target.id)
        log_action(chat_id, 'ban', actor.id, target.id)

        if actor.id not in whitelist:
            count = count_recent_actions(chat_id, actor.id, 'ban', window_min)
            if count >= ban_thresh:
                # 💥 مهار فوری خرابکاری (Auto-Demote)
                demote_admin(chat_id, actor.id)
                reason = f"بن دسته‌جمعی خودکار ({count} بن در {window_min} دقیقه)"
                flag_id = add_flag(chat_id, actor.id, reason, 0)
                log_action(chat_id, 'auto_demote_ban', 0, actor.id, reason)
                notify_super_admin(chat_id, actor.id, group[1], reason, flag_id, auto_demoted=True)
                bot.send_message(chat_id, f"🚨 <b>هشدار ضدخرابکاری:</b> دسترسی ادمین <code>{actor.id}</code> به دلیل بن مکرر فوراً سلب شد!")

    # 2. محدودسازی کاربر (Restrict Detection)
    elif new_status == 'restricted' and old_status != 'restricted':
        log_admin_action(chat_id, actor.id, 'restrict', target.id)
        log_action(chat_id, 'restrict', actor.id, target.id)

        if actor.id not in whitelist:
            count = count_recent_actions(chat_id, actor.id, 'restrict', window_min)
            if count >= restrict_thresh:
                demote_admin(chat_id, actor.id)
                reason = f"محدودسازی دسته‌جمعی خودکار ({count} مورد در {window_min} دقیقه)"
                flag_id = add_flag(chat_id, actor.id, reason, 0)
                log_action(chat_id, 'auto_demote_restrict', 0, actor.id, reason)
                notify_super_admin(chat_id, actor.id, group[1], reason, flag_id, auto_demoted=True)
                bot.send_message(chat_id, f"🚨 <b>هشدار:</b> دسترسی ادمین <code>{actor.id}</code> به دلیل محدودسازی بیش از حد اعضا سلب شد!")

    # 3. ارتقای کاربر به ادمین (Promote Detection & Lock)
    elif new_status == 'administrator' and old_status != 'administrator':
        log_action(chat_id, 'promote', actor.id, target.id)

        if strict_lock and actor.id not in whitelist:
            # عزل فوری هم کاربر جدید و هم ادمین ارتقادهنده
            demote_admin(chat_id, target.id)
            demote_admin(chat_id, actor.id)
            reason = f"ارتقای غیرمجاز کاربر {target.id} توسط ادمین فاقد صلاحیت {actor.id}"
            flag_id = add_flag(chat_id, actor.id, reason, 0)
            log_action(chat_id, 'auto_demote_unauthorized_promoter', 0, actor.id, reason)
            notify_super_admin(chat_id, actor.id, group[1], reason, flag_id, auto_demoted=True)
            bot.send_message(chat_id, "⚠️ <b>قفل ارتقا فعال است:</b> هر دو ادمین خاطی خلع دسترسی شدند.")

# ---------------------------------------------------------
# دکمه‌های شیشه‌ای تلگرام
# ---------------------------------------------------------
@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    if call.from_user.id != SUPER_ADMIN_ID:
        bot.answer_callback_query(call.id, "❌ شما دسترسی لازم را ندارید.", show_alert=True)
        return

    data = call.data
    try:
        if data.startswith('rem_'):
            _, chat_id, admin_id, flag_id = data.split('_')
            chat_id, admin_id, flag_id = int(chat_id), int(admin_id), int(flag_id)
            demote_admin(chat_id, admin_id)
            resolve_flag(flag_id, 'removed')
            log_action(chat_id, 'manual_callback_demote', call.from_user.id, admin_id)
            bot.edit_message_text(f"✅ ادمین <code>{admin_id}</code> با موفقیت عزل شد.", call.message.chat.id, call.message.message_id)
            bot.send_message(chat_id, "⚠️ یکی از مدیران گروه توسط سوپرادمین عزل شد.")

        elif data.startswith('protect_'):
            _, chat_id, admin_id, flag_id = data.split('_')
            chat_id, admin_id, flag_id = int(chat_id), int(admin_id), int(flag_id)
            add_protected_admin(chat_id, admin_id)
            resolve_flag(flag_id, 'whitelisted')
            bot.edit_message_text(f"🛡 ادمین <code>{admin_id}</code> به لیست سفید اضافه شد.", call.message.chat.id, call.message.message_id)

        elif data.startswith('ign_'):
            flag_id = int(data.split('_')[1])
            resolve_flag(flag_id, 'ignored')
            bot.edit_message_text("✅ گزارش نادیده گرفته و مختومه شد.", call.message.chat.id, call.message.message_id)

    except Exception as e:
        bot.answer_callback_query(call.id, f"خطا: {e}", show_alert=True)

# ---------------------------------------------------------
# روت‌های وب و کران جاب
# ---------------------------------------------------------
@app.route('/api/webhook', methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_str = request.get_data().decode('utf-8')
        update = types.Update.de_json(json_str)
        bot.process_new_updates([update])
        return 'OK', 200
    return 'Bad Request', 400

@app.route('/api/cron', methods=['GET'])
def cron_check():
    secret = request.args.get('secret', '')
    if not hmac.compare_digest(secret, CRON_SECRET):
        return 'Forbidden', 403

    now = int(time.time())
    for g in get_all_groups():
        chat_id, title, owner_id, threshold, last_activity, chat_type, _ = g
        days_inactive = (now - last_activity) / 86400

        if days_inactive >= threshold:
            warned_at = get_pending_warning(chat_id)
            if not warned_at:
                set_pending_warning(chat_id, now)
                try:
                    bot.send_message(chat_id, WARNING_MESSAGE)
                except Exception as e:
                    logging.error(f"Error sending warning to {chat_id}: {e}")
            elif now - warned_at >= 86400: # پس از گذشت ۲۴ ساعت از هشدار
                purge_unprotected_admins(chat_id)
                clear_pending_warning(chat_id)

    return 'Cron Finished Successfully', 200

def purge_unprotected_admins(chat_id):
    """عزل تمام ادمین‌های غیرمحافظت‌شده به دلیل عدم فعالیت مالک"""
    group = get_group(chat_id)
    if not group:
        return
    owner_id = group[2]
    protected = get_protected_admins(chat_id) + [owner_id, SUPER_ADMIN_ID, bot.get_me().id]
    try:
        admins = bot.get_chat_administrators(chat_id)
    except Exception as e:
        logging.error(f"Cannot get admins for {chat_id}: {e}")
        return

    removed = []
    for admin in admins:
        if admin.status == 'creator' or admin.user.id in protected:
            continue
        if demote_admin(chat_id, admin.user.id):
            removed.append(admin.user.id)
            log_action(chat_id, 'inactivity_purge', 0, admin.user.id, "حذف به دلیل خواب مالک گروه")

    if removed:
        bot.send_message(chat_id, f"🛡 <b>عملیات پاکسازی امنیتی:</b> تعداد {len(removed)} ادمین به دلیل عدم حضور مالک عزل شدند.")

# ---------------------------------------------------------
# پنل تحت وب (Flask Dashboard)
# ---------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} | پنل امنیت گروه</title>
    <style>
        * { box-sizing: border-box; font-family: 'Segoe UI', Tahoma, sans-serif; }
        body { background: #f0f2f5; margin: 0; padding: 0; color: #333; }
        nav { background: #1e293b; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
        nav a { color: #f8fafc; text-decoration: none; margin-left: 20px; font-weight: 500; }
        nav a:hover { color: #38bdf8; }
        .container { max-width: 1100px; margin: 30px auto; background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        h1, h2 { color: #0f172a; margin-top: 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px 15px; text-align: right; border-bottom: 1px solid #e2e8f0; }
        th { background: #f8fafc; color: #475569; font-weight: 600; }
        .badge { padding: 5px 10px; border-radius: 20px; font-size: 13px; font-weight: bold; }
        .badge-green { background: #dcfce7; color: #15803d; }
        .badge-red { background: #fee2e2; color: #b91c1c; }
        .badge-blue { background: #e0f2fe; color: #0369a1; }
        .btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; text-decoration: none; display: inline-block; font-size: 14px; font-weight: 500; }
        .btn-blue { background: #0284c7; color: #fff; }
        .btn-red { background: #ef4444; color: #fff; }
        .btn-green { background: #22c55e; color: #fff; }
        .btn:hover { opacity: 0.9; }
        input, select { padding: 9px 12px; border: 1px solid #cbd5e1; border-radius: 6px; margin: 5px 0; width: 100%; max-width: 300px; }
        .form-inline { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 20px; }
        .card { background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 8px; margin-bottom: 25px; }
    </style>
</head>
<body>
    {% if session.get('logged_in') %}
    <nav>
        <div>
            <a href="{{ url_for('dashboard') }}">📊 داشبورد گروه‌ها</a>
            <a href="{{ url_for('flags_page') }}">🚨 گزارش‌ها و تخلفات</a>
        </div>
        <div>
            <a href="{{ url_for('logout') }}" style="color: #f87171;">خروج 🚪</a>
        </div>
    </nav>
    {% endif %}
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        pwd = request.form.get('password', '')
        if hmac.compare_digest(pwd, PANEL_PASSWORD):
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        error = "رمز عبور نادرست است."

    template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
    <div style="max-width: 380px; margin: 50px auto; text-align: center;">
        <h2>ورود به پنل مدیریت امنیت</h2>
        {% if error %}<p style="color: red;">{{ error }}</p>{% endif %}
        <form method="post">
            <input type="password" name="password" placeholder="رمز پنل..." required><br><br>
            <button class="btn btn-blue" style="width: 100%;">ورود به سیستم</button>
        </form>
    </div>
    """)
    return render_template_string(template, title="ورود", error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    groups = get_all_groups()
    now = int(time.time())
    processed_groups = []
    for g in groups:
        chat_id, title, owner_id, threshold, last_activity, chat_type, strict = g
        days_inactive = int((now - last_activity) / 86400)
        processed_groups.append({
            'chat_id': chat_id,
            'title': title,
            'owner_id': owner_id,
            'threshold': threshold,
            'days_inactive': days_inactive,
            'is_warned': days_inactive >= threshold,
            'strict': strict
        })

    content = """
    <h1>داشبورد مدیریت امنیت گروه‌ها</h1>
    <table>
        <thead>
            <tr>
                <th>نام گروه</th>
                <th>مالک</th>
                <th>وضعیت فعالیت مالک</th>
                <th>قفل ارتقا</th>
                <th>عملیات</th>
            </tr>
        </thead>
        <tbody>
            {% for g in groups %}
            <tr>
                <td><b>{{ g.title }}</b></td>
                <td><code>{{ g.owner_id }}</code></td>
                <td>
                    {% if g.is_warned %}
                        <span class="badge badge-red">⚠️ غیرفعال ({{ g.days_inactive }} روز)</span>
                    {% else %}
                        <span class="badge badge-green">فعال ({{ g.days_inactive }} روز پیش)</span>
                    {% endif %}
                </td>
                <td>
                    {% if g.strict %}
                        <span class="badge badge-blue">فعال ✅</span>
                    {% else %}
                        <span class="badge badge-red">غیرفعال ❌</span>
                    {% endif %}
                </td>
                <td>
                    <a href="{{ url_for('group_detail', chat_id=g.chat_id) }}" class="btn btn-blue">مدیریت و تنظیمات</a>
                </td>
            </tr>
            {% else %}
            <tr><td colspan="5" style="text-align: center;">هیچ گروهی ثبت نشده است. از ربات تلگرام /register استفاده کنید.</td></tr>
            {% endfor %}
        </tbody>
    </table>
    """
    template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
    return render_template_string(template, title="داشبورد", groups=processed_groups)

@app.route('/group/<int:chat_id>')
@login_required
def group_detail(chat_id):
    group = get_group(chat_id)
    if not group:
        return "گروه یافت نشد", 404

    protected = get_protected_admins(chat_id)
    try:
        tg_admins = bot.get_chat_administrators(chat_id)
    except Exception:
        tg_admins = []

    admin_list = []
    bot_id = bot.get_me().id
    for a in tg_admins:
        if a.user.id == bot_id:
            continue
        admin_list.append({
            'id': a.user.id,
            'name': a.user.first_name,
            'is_creator': (a.status == 'creator'),
            'is_protected': (a.user.id in protected)
        })

    logs = get_action_log(chat_id, limit=25)
    formatted_logs = []
    for l in logs:
        action, actor, target, details, ts = l
        formatted_logs.append({
            'action': action,
            'actor': actor,
            'target': target,
            'details': details or '-',
            'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
        })

    content = """
    <h2>⚙️ مدیریت گروه: {{ group[1] }}</h2>
    
    <div class="card">
        <h3>تنظیمات ضد خرابکاری و قوانین گروه</h3>
        <form method="post" action="{{ url_for('update_group_cfg', chat_id=group[0]) }}">
            <div class="form-inline">
                <div>
                    <label>آستانه خواب مالک (روز):</label><br>
                    <input type="number" name="threshold_days" value="{{ group[3] }}" required>
                </div>
                <div>
                    <label>حداکثر بن در بازه:</label><br>
                    <input type="number" name="ban_threshold" value="{{ group[7] }}" required>
                </div>
                <div>
                    <label>حداکثر میوت در بازه:</label><br>
                    <input type="number" name="restrict_threshold" value="{{ group[8] }}" required>
                </div>
                <div>
                    <label>بازه زمانی بررسی (دقیقه):</label><br>
                    <input type="number" name="window_minutes" value="{{ group[9] }}" required>
                </div>
            </div>
            <div>
                <label>
                    <input type="checkbox" name="strict_promote_lock" value="1" {% if group[6] %}checked{% endif %} style="width: auto;">
                    قفل اکید ارتقای ادمین (فقط مالک و لیست سفید حق ادمین کردن دارند)
                </label>
            </div>
            <br>
            <button class="btn btn-blue">💾 ذخیره تغییرات</button>
        </form>
    </div>

    <h3>👥 لیست ادمین‌ها و سطوح دسترسی</h3>
    <table>
        <thead>
            <tr>
                <th>نام و مشخصات</th>
                <th>شناسه (ID)</th>
                <th>نقش / وضعیت</th>
                <th>حفاظت (لیست سفید)</th>
                <th>اقدام فوری</th>
            </tr>
        </thead>
        <tbody>
            {% for a in admins %}
            <tr>
                <td><b>{{ a.name }}</b></td>
                <td><code>{{ a.id }}</code></td>
                <td>
                    {% if a.is_creator %}
                        <span class="badge badge-blue">مالک اصلی 👑</span>
                    {% else %}
                        مدیر
                    {% endif %}
                </td>
                <td>
                    {% if not a.is_creator %}
                        {% if a.is_protected %}
                            <form method="post" action="{{ url_for('toggle_protect', chat_id=group[0], admin_id=a.id, action='unprotect') }}" style="display:inline;">
                                <button class="btn btn-green">محافظت‌شده ✅</button>
                            </form>
                        {% else %}
                            <form method="post" action="{{ url_for('toggle_protect', chat_id=group[0], admin_id=a.id, action='protect') }}" style="display:inline;">
                                <button class="btn btn-blue">عادی (حفاظت نشده)</button>
                            </form>
                        {% endif %}
                    {% else %}
                        -
                    {% endif %}
                </td>
                <td>
                    {% if not a.is_creator %}
                    <form method="post" action="{{ url_for('demote_admin_web', chat_id=group[0], admin_id=a.id) }}" onsubmit="return confirm('آیا از عزل این ادمین مطمئن هستید؟');" style="display:inline;">
                        <button class="btn btn-red">عزل ادمین ❌</button>
                    </form>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <h3 style="margin-top: 40px;">📜 لاگ رویدادها و فعالیت‌های اخیر</h3>
    <table>
        <thead>
            <tr>
                <th>عملیات</th>
                <th>مجری</th>
                <th>هدف</th>
                <th>توضیحات</th>
                <th>زمان</th>
            </tr>
        </thead>
        <tbody>
            {% for l in logs %}
            <tr>
                <td><code>{{ l.action }}</code></td>
                <td><code>{{ l.actor }}</code></td>
                <td><code>{{ l.target }}</code></td>
                <td>{{ l.details }}</td>
                <td>{{ l.time }}</td>
            </tr>
            {% else %}
            <tr><td colspan="5" style="text-align:center;">هیچ لاگی ثبت نشده است.</td></tr>
            {% endfor %}
        </tbody>
    </table>
    """
    template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
    return render_template_string(template, title=f"مدیریت {group[1]}", group=group, admins=admin_list, logs=formatted_logs)

@app.route('/group/<int:chat_id>/config', methods=['POST'])
@login_required
def update_group_cfg(chat_id):
    threshold_days = int(request.form.get('threshold_days', 30))
    ban_thresh = int(request.form.get('ban_threshold', 5))
    restrict_thresh = int(request.form.get('restrict_threshold', 8))
    window_min = int(request.form.get('window_minutes', 5))
    strict_promote = bool(request.form.get('strict_promote_lock'))

    update_group_settings(chat_id, threshold_days, strict_promote, ban_thresh, restrict_thresh, window_min)
    return redirect(url_for('group_detail', chat_id=chat_id))

@app.route('/group/<int:chat_id>/protect_toggle/<int:admin_id>/<action>', methods=['POST'])
@login_required
def toggle_protect(chat_id, admin_id, action):
    if action == 'protect':
        add_protected_admin(chat_id, admin_id)
    else:
        remove_protected_admin(chat_id, admin_id)
    return redirect(url_for('group_detail', chat_id=chat_id))

@app.route('/group/<int:chat_id>/demote/<int:admin_id>', methods=['POST'])
@login_required
def demote_admin_web(chat_id, admin_id):
    if demote_admin(chat_id, admin_id):
        log_action(chat_id, 'panel_demote', 0, admin_id, "عزل دستی از طریق پنل وب")
        try:
            bot.send_message(chat_id, f"⚠️ دسترسی ادمین <code>{admin_id}</code> از طریق پنل مدیریت سلب شد.")
        except Exception:
            pass
    return redirect(url_for('group_detail', chat_id=chat_id))

@app.route('/flags')
@login_required
def flags_page():
    raw_flags = get_flags('pending')
    flags = []
    for f in raw_flags:
        fid, chat_id, admin_id, reason, reported_by, status, ts = f
        group = get_group(chat_id)
        flags.append({
            'id': fid,
            'chat_id': chat_id,
            'group_title': group[1] if group else str(chat_id),
            'admin_id': admin_id,
            'reason': reason,
            'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
        })

    content = """
    <h2>🚨 گزارش‌ها و هشدارهای امنیتی بررسی‌نشده</h2>
    <table>
        <thead>
            <tr>
                <th>گروه</th>
                <th>ادمین خاطی</th>
                <th>علت تخلف</th>
                <th>زمان</th>
                <th>عملیات</th>
            </tr>
        </thead>
        <tbody>
            {% for f in flags %}
            <tr>
                <td><b>{{ f.group_title }}</b></td>
                <td><code>{{ f.admin_id }}</code></td>
                <td><span style="color: #b91c1c;">{{ f.reason }}</span></td>
                <td>{{ f.time }}</td>
                <td>
                    <form method="post" action="{{ url_for('resolve_flag_web', flag_id=f.id, act='demote') }}" style="display:inline;">
                        <button class="btn btn-red">عزل ادمین ❌</button>
                    </form>
                    <form method="post" action="{{ url_for('resolve_flag_web', flag_id=f.id, act='ignore') }}" style="display:inline;">
                        <button class="btn btn-green">نادیده گرفتن ✅</button>
                    </form>
                </td>
            </tr>
            {% else %}
            <tr><td colspan="5" style="text-align: center;">هیچ گزارش جدیدی وجود ندارد. همه چیز امن است! ✨</td></tr>
            {% endfor %}
        </tbody>
    </table>
    """
    template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', content)
    return render_template_string(template, title="گزارش‌ها", flags=flags)

@app.route('/flags/resolve/<int:flag_id>/<act>', methods=['POST'])
@login_required
def resolve_flag_web(flag_id, act):
    f = get_flag(flag_id)
    if f:
        chat_id, admin_id = f[1], f[2]
        if act == 'demote':
            demote_admin(chat_id, admin_id)
            resolve_flag(flag_id, 'demoted_via_panel')
            log_action(chat_id, 'flag_demote_panel', 0, admin_id)
        else:
            resolve_flag(flag_id, 'ignored_via_panel')
    return redirect(url_for('flags_page'))

# ---------------------------------------------------------
# راه‌اندازی برنامه
# ---------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
