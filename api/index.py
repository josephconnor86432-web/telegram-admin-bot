import os
import time
import hmac
import html
import logging
from functools import wraps
from contextlib import contextmanager

import psycopg2
from psycopg2 import pool
from flask import Flask, request, session, redirect, url_for, render_template_string
import telebot
from telebot import types

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# متغیرهای محیطی
BOT_TOKEN = os.environ.get('BOT_TOKEN', '')
SUPER_ADMIN_ID = int(os.environ.get('SUPER_ADMIN_ID', '0').strip())
DATABASE_URL = os.environ.get('DATABASE_URL', '')
PANEL_PASSWORD = os.environ.get('PANEL_PASSWORD', 'admin123')
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())
CRON_SECRET = os.environ.get('CRON_SECRET', 'cron_secure_token')

WARNING_MESSAGE = """⚠️ <b>هشدار امنیتی:</b>
مالک این گروه برای مدت طولانی فعالیتی نداشته است.
در صورتی که ظرف ۲۴ ساعت آینده پیامی از سوی مالک ارسال نشود، ادمین‌های غیرمحافظت‌شده به صورت خودکار عزل خواهند شد."""

bot = telebot.TeleBot(BOT_TOKEN, threaded=False, parse_mode='HTML')
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# ---------------------------------------------------------
# پایگاه داده سازگار با سرورلس
# ---------------------------------------------------------
def create_pool():
    return pool.ThreadedConnectionPool(1, 5, DATABASE_URL, sslmode='require')

db_pool = None
try:
    if DATABASE_URL:
        db_pool = create_pool()
except Exception as e:
    logging.error(f"Initial DB Pool Error: {e}")

@contextmanager
def get_db():
    global db_pool
    conn = None
    try:
        if not db_pool:
            db_pool = create_pool()
        conn = db_pool.getconn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
    except Exception:
        if conn and db_pool:
            try:
                db_pool.putconn(conn, close=True)
            except Exception:
                pass
        db_pool = create_pool()
        conn = db_pool.getconn()

    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"Database Error: {e}")
        raise
    finally:
        if conn and db_pool:
            db_pool.putconn(conn)

def init_db():
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

try:
    if DATABASE_URL:
        init_db()
except Exception as e:
    logging.error(f"Init DB Failed: {e}")

# ---------------------------------------------------------
# توابع کمکی دیتابیس
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
            c.execute("SELECT chat_id, chat_title, owner_id, threshold_days, last_owner_activity, chat_type, strict_promote_lock, ban_threshold, restrict_threshold, window_minutes FROM groups ORDER BY chat_title")
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

def get_action_log(chat_id, limit=30):
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
# توابع مدیریتی ربات
# ---------------------------------------------------------
def get_group_owner(chat_id):
    try:
        admins = bot.get_chat_administrators(chat_id)
        for a in admins:
            if a.status == 'creator':
                return a.user.id
    except Exception as e:
        logging.error(f"Creator lookup failed for {chat_id}: {e}")
    return None

def demote_admin(chat_id, admin_id):
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
        logging.error(f"Demote failed: {e}")
        try:
            bot.ban_chat_member(chat_id, admin_id)
            bot.unban_chat_member(chat_id, admin_id)
            return True
        except Exception:
            return False

def notify_super_admin(chat_id, admin_id, group_title, reason, flag_id, auto_demoted=False):
    try:
        info = bot.get_chat_member(chat_id, admin_id).user
        name = info.first_name or "ناشناس"
        username = f"@{info.username}" if info.username else "ندارد"
    except Exception:
        name = "ناشناس"
        username = "ندارد"

    status_str = "🔴 <b>ادمین خاطی به صورت خودکار عزل شد!</b>" if auto_demoted else "⚠️ <b>اقدام مورد نیاز:</b>"
    text = (
        f"🚨 <b>هشدار امنیتی ربات!</b>\n\n"
        f"{status_str}\n"
        f"📍 <b>گروه:</b> {html.escape(str(group_title))}\n"
        f"👤 <b>ادمین:</b> {html.escape(name)} ({username})\n"
        f"🆔 <b>آیدی:</b> <code>{admin_id}</code>\n"
        f"💬 <b>علت:</b> {html.escape(reason)}\n"
        f"⏰ <b>زمان:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )

    markup = types.InlineKeyboardMarkup(row_width=2)
    if not auto_demoted:
        markup.add(
            types.InlineKeyboardButton("🔴 عزل فوری", callback_data=f"rem_{chat_id}_{admin_id}_{flag_id}"),
            types.InlineKeyboardButton("✅ نادیده گرفتن", callback_data=f"ign_{flag_id}")
        )
    else:
        markup.add(
            types.InlineKeyboardButton("🛡 افزودن به لیست سفید", callback_data=f"protect_{chat_id}_{admin_id}_{flag_id}"),
            types.InlineKeyboardButton("✅ تأیید", callback_data=f"ign_{flag_id}")
        )

    try:
        bot.send_message(SUPER_ADMIN_ID, text, reply_markup=markup)
    except Exception as e:
        logging.error(f"Super admin notify error: {e}")

# ---------------------------------------------------------
# کیبوردهای تلگرام (Reply & Inline)
# ---------------------------------------------------------
def get_pv_keyboard():
    """کیبورد اصلی و ثابت پایین صفحه در پی‌وی"""
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        types.KeyboardButton("👥 لیست افراد تحت پایش"),
        types.KeyboardButton("📋 وضعیت گروه‌ها")
    )
    markup.add(
        types.KeyboardButton("🚨 هشدارهای فعال"),
        types.KeyboardButton("📊 آمار و تنظیمات")
    )
    return markup

def get_pv_group_detail_markup(chat_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("👥 مشاهده ادمین‌های این گروه", callback_data=f"pv_admins_{chat_id}"),
        types.InlineKeyboardButton("🛡 ادمین‌های مصون", callback_data=f"pv_protected_{chat_id}")
    )
    markup.add(
        types.InlineKeyboardButton("📜 لاگ فعالیت‌ها", callback_data=f"pv_logs_{chat_id}"),
        types.InlineKeyboardButton("🔒 سوئیچ قفل ارتقا", callback_data=f"pv_toggle_lock_{chat_id}")
    )
    markup.add(
        types.InlineKeyboardButton("🔙 بازگشت به لیست گروه‌ها", callback_data="pv_monitored_groups")
    )
    return markup

# ---------------------------------------------------------
# هندلرهای پیام‌های تلگرام
# ---------------------------------------------------------
@bot.message_handler(commands=['start', 'menu', 'panel'])
def cmd_start(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        bot.reply_to(message, "⛔️ این ربات اختصاصی است.")
        return

    if message.chat.type == 'private':
        text = (
            "👑 <b>به پنل پایش و مدیریت امنیت ربات خوش آمدید!</b>\n\n"
            "از طریق دکمه‌های پایین صفحه یا دستورات زیر می‌توانید گروه‌ها و ادمین‌های تحت نظر را بررسی و مدیریت کنید."
        )
        bot.send_message(message.chat.id, text, reply_markup=get_pv_keyboard())
    else:
        bot.reply_to(message, "🤖 برای دسترسی به پنل مدیریت جامع، به پی‌وی ربات مراجعه کنید.")

# هندلر کلیک روی دکمه‌های کیبورد پایین صفحه در پی‌وی یا دستورات متنی
@bot.message_handler(func=lambda m: m.text in ["👥 لیست افراد تحت پایش", "📋 وضعیت گروه‌ها", "/monitored", "/list_admins"])
def handle_monitored_button(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return

    groups = get_all_groups()
    if not groups:
        bot.reply_to(message, "❌ هنوز هیچ گروهی ثبت نشده است. ابتدا در گروه دستور <code>/register</code> را بزنید.", reply_markup=get_pv_keyboard())
        return

    markup = types.InlineKeyboardMarkup(row_width=1)
    text = "👥 <b>لیست گروه‌های تحت پایش:</b>\nبرای مشاهده وضعیت ادمین‌ها روی گروه مورد نظر کلیک کنید:\n\n"
    
    now = int(time.time())
    for g in groups:
        chat_id, title, owner_id, threshold, last_act = g[0], g[1], g[2], g[3], g[4]
        days_inactive = int((now - last_act) / 86400)
        status_icon = "🔴" if days_inactive >= threshold else "🟢"
        text += f"{status_icon} <b>{html.escape(title)}</b>\n🆔 <code>{chat_id}</code> | آخرین حضور مالک: {days_inactive} روز پیش\n\n"
        markup.add(types.InlineKeyboardButton(f"⚙️ مدیریت ادمین‌های {title}", callback_data=f"pv_admins_{chat_id}"))

    bot.send_message(message.chat.id, text, reply_markup=markup)

@bot.message_handler(func=lambda m: m.text == "🚨 هشدارهای فعال")
def handle_flags_button(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    flags = get_flags('pending')
    if not flags:
        bot.reply_to(message, "✨ هیچ گزارش یا رفتار مشکوکی در حال حاضر وجود ندارد.", reply_markup=get_pv_keyboard())
        return

    text = "🚨 <b>هشدارهای امنیتی بررسی‌نشده:</b>\n\n"
    markup = types.InlineKeyboardMarkup(row_width=1)
    for f in flags[:8]:
        text += f"▫️ ادمین: <code>{f[2]}</code> | گروه: <code>{f[1]}</code>\nعلت: {html.escape(f[3])}\n\n"
        markup.add(types.InlineKeyboardButton(f"عزل ادمین {f[2]}", callback_data=f"rem_{f[1]}_{f[2]}_{f[0]}"))

    bot.send_message(message.chat.id, text, reply_markup=markup)

@bot.message_handler(func=lambda m: m.text == "📊 آمار و تنظیمات")
def handle_stats_button(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    groups = get_all_groups()
    flags = get_flags('pending')
    text = (
        f"📊 <b>آمار کلی سیستم:</b>\n\n"
        f"▫️ تعداد کل گروه‌ها: <b>{len(groups)} گروه</b>\n"
        f"▫️ هشدارهای معلق: <b>{len(flags)} مورد</b>\n"
        f"▫️ وضعیت ضدخرابکاری: <b>فعال و هوشمند 🛡</b>\n"
    )
    bot.send_message(message.chat.id, text, reply_markup=get_pv_keyboard())

@bot.message_handler(commands=['register'])
def register_group(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        bot.reply_to(message, "❌ فقط سوپرادمین اجازه ثبت دارد.")
        return
    chat = message.chat
    if chat.type not in ['group', 'supergroup']:
        bot.reply_to(message, "❌ این دستور باید در داخل گروه اجرا شود.")
        return

    try:
        bm = bot.get_chat_member(chat.id, bot.get_me().id)
        if bm.status != 'administrator' or not bm.can_promote_members or not bm.can_restrict_members:
            bot.reply_to(message, "❌ ربات باید دسترسی کامل ادمین (Promote/Restrict) داشته باشد.")
            return
    except Exception as e:
        bot.reply_to(message, f"خطا: {e}")
        return

    owner_id = get_group_owner(chat.id) or SUPER_ADMIN_ID
    add_or_update_group(chat.id, chat.title, owner_id, chat.type)
    bot.reply_to(message, f"✅ گروه <b>{html.escape(chat.title)}</b> با شناسه <code>{chat.id}</code> ثبت شد.\n👑 مالک: <code>{owner_id}</code>")

@bot.message_handler(commands=['protect_admin'])
def cmd_protect_admin(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    parts = message.text.split()
    chat_id = None
    target_id = None

    if message.chat.type in ['group', 'supergroup']:
        chat_id = message.chat.id
        target_id = message.reply_to_message.from_user.id if message.reply_to_message else (int(parts[1]) if len(parts) > 1 else None)
    else:
        if len(parts) >= 3:
            chat_id = int(parts[1])
            target_id = int(parts[2])

    if not chat_id or not target_id:
        bot.reply_to(message, "راهنما: در گروه <code>/protect_admin USER_ID</code> یا در پی‌وی <code>/protect_admin CHAT_ID USER_ID</code>")
        return

    add_protected_admin(chat_id, target_id)
    bot.reply_to(message, f"🛡 ادمین <code>{target_id}</code> در گروه <code>{chat_id}</code> مصون شد.")

@bot.message_handler(commands=['remove_admin'])
def cmd_remove_admin(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    parts = message.text.split()
    chat_id = None
    target_id = None

    if message.chat.type in ['group', 'supergroup']:
        chat_id = message.chat.id
        target_id = message.reply_to_message.from_user.id if message.reply_to_message else (int(parts[1]) if len(parts) > 1 else None)
    else:
        if len(parts) >= 3:
            chat_id = int(parts[1])
            target_id = int(parts[2])

    if not chat_id or not target_id:
        bot.reply_to(message, "راهنما: در گروه <code>/remove_admin USER_ID</code> یا در پی‌وی <code>/remove_admin CHAT_ID USER_ID</code>")
        return

    if demote_admin(chat_id, target_id):
        log_action(chat_id, 'manual_demote', message.from_user.id, target_id, "عزل دستی")
        bot.reply_to(message, f"✅ ادمین <code>{target_id}</code> در گروه <code>{chat_id}</code> عزل شد.")
    else:
        bot.reply_to(message, "❌ خطا در عزل ادمین.")

# ردگیری پیام مالک در گروه
@bot.message_handler(func=lambda m: True, content_types=['text', 'photo', 'video', 'sticker', 'document', 'voice', 'audio', 'location'])
def track_owner_activity(message):
    if message.chat.type not in ['group', 'supergroup']:
        return
    group = get_group(message.chat.id)
    if not group:
        return
    owner_id = group[2]
    if message.from_user and message.from_user.id == owner_id:
        update_owner_activity(message.chat.id, int(time.time()))
        if get_pending_warning(message.chat.id):
            clear_pending_warning(message.chat.id)
            bot.send_message(message.chat.id, "✅ <b>فعالیت مالک تأیید شد.</b> عملیات خلع ادمین‌ها لغو شد.")

# رصد تخلفات ادمین‌ها
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

    if actor.id == target.id:
        return

    owner_id = group[2]
    strict_lock = group[6]
    ban_thresh = group[7]
    restrict_thresh = group[8]
    window_min = group[9]
    whitelist = get_protected_admins(chat_id) + [owner_id, SUPER_ADMIN_ID, bot.get_me().id]

    if new_status in ['kicked', 'banned'] and old_status not in ['kicked', 'banned']:
        log_admin_action(chat_id, actor.id, 'ban', target.id)
        log_action(chat_id, 'ban', actor.id, target.id)
        if actor.id not in whitelist:
            count = count_recent_actions(chat_id, actor.id, 'ban', window_min)
            if count >= ban_thresh:
                demote_admin(chat_id, actor.id)
                reason = f"بن دسته‌جمعی ({count} بن در {window_min} دقیقه)"
                flag_id = add_flag(chat_id, actor.id, reason, 0)
                log_action(chat_id, 'auto_demote_ban', 0, actor.id, reason)
                notify_super_admin(chat_id, actor.id, group[1], reason, flag_id, auto_demoted=True)
                bot.send_message(chat_id, f"🚨 دسترسی ادمین <code>{actor.id}</code> به دلیل بن‌های مکرر فوراً سلب شد.")

    elif new_status == 'restricted' and old_status != 'restricted':
        log_admin_action(chat_id, actor.id, 'restrict', target.id)
        log_action(chat_id, 'restrict', actor.id, target.id)
        if actor.id not in whitelist:
            count = count_recent_actions(chat_id, actor.id, 'restrict', window_min)
            if count >= restrict_thresh:
                demote_admin(chat_id, actor.id)
                reason = f"محدودسازی دسته‌جمعی ({count} مورد در {window_min} دقیقه)"
                flag_id = add_flag(chat_id, actor.id, reason, 0)
                log_action(chat_id, 'auto_demote_restrict', 0, actor.id, reason)
                notify_super_admin(chat_id, actor.id, group[1], reason, flag_id, auto_demoted=True)
                bot.send_message(chat_id, f"🚨 دسترسی ادمین <code>{actor.id}</code> به دلیل محدودسازی بیش از حد اعضا سلب شد.")

    elif new_status == 'administrator' and old_status != 'administrator':
        log_action(chat_id, 'promote', actor.id, target.id)
        if strict_lock and actor.id not in whitelist:
            demote_admin(chat_id, target.id)
            demote_admin(chat_id, actor.id)
            reason = f"ارتقای غیرمجاز کاربر {target.id} توسط {actor.id}"
            flag_id = add_flag(chat_id, actor.id, reason, 0)
            log_action(chat_id, 'auto_demote_unauthorized_promoter', 0, actor.id, reason)
            notify_super_admin(chat_id, actor.id, group[1], reason, flag_id, auto_demoted=True)
            bot.send_message(chat_id, "⚠️ <b>قفل ارتقا:</b> ادمین‌های غیرمجاز خلع شدند.")

# ---------------------------------------------------------
# کال‌بک‌های شیشه‌ای پی‌وی و هشدارها
# ---------------------------------------------------------
@bot.callback_query_handler(func=lambda call: True)
def handle_callbacks(call):
    if call.from_user.id != SUPER_ADMIN_ID:
        bot.answer_callback_query(call.id, "❌ دسترسی غیرمجاز.", show_alert=True)
        return

    data = call.data
    try:
        if data == "pv_monitored_groups":
            groups = get_all_groups()
            markup = types.InlineKeyboardMarkup(row_width=1)
            text = "👥 <b>انتخاب گروه جهت بررسی افراد تحت پایش:</b>\n\n"
            for g in groups:
                markup.add(types.InlineKeyboardButton(f"⚙️ {g[1]}", callback_data=f"pv_admins_{g[0]}"))
            bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=markup)
            bot.answer_callback_query(call.id)

        elif data.startswith("pv_admins_"):
            chat_id = int(data.split("_")[2])
            g = get_group(chat_id)
            if not g:
                bot.answer_callback_query(call.id, "گروه یافت نشد!", show_alert=True)
                return

            protected = get_protected_admins(chat_id)
            try:
                tg_admins = bot.get_chat_administrators(chat_id)
            except Exception as e:
                bot.answer_callback_query(call.id, f"خطا در ارتباط با تلگرام: {e}", show_alert=True)
                return

            bot_id = bot.get_me().id
            markup = types.InlineKeyboardMarkup(row_width=2)
            text = f"👥 <b>لیست تمام ادمین‌های گروه: {html.escape(g[1])}</b>\n\n"

            for a in tg_admins:
                u = a.user
                if u.id == bot_id:
                    continue
                name = html.escape(u.first_name or "ناشناس")
                if a.status == 'creator':
                    text += f"👑 <b>{name}</b> (<code>{u.id}</code>) - مالک اصلی\n\n"
                elif u.id in protected:
                    text += f"🛡 <b>{name}</b> (<code>{u.id}</code>) - [محافظت‌شده ✅]\n\n"
                    markup.add(
                        types.InlineKeyboardButton(f"❌ لغو مصونیت {name[:10]}", callback_data=f"pv_unp_{chat_id}_{u.id}"),
                        types.InlineKeyboardButton(f"🛑 عزل {name[:10]}", callback_data=f"pv_dem_{chat_id}_{u.id}")
                    )
                else:
                    text += f"⚠️ <b>{name}</b> (<code>{u.id}</code>) - [تحت پایش ⚠️]\n\n"
                    markup.add(
                        types.InlineKeyboardButton(f"🛡 محافظت {name[:10]}", callback_data=f"pv_prt_{chat_id}_{u.id}"),
                        types.InlineKeyboardButton(f"🛑 عزل {name[:10]}", callback_data=f"pv_dem_{chat_id}_{u.id}")
                    )

            markup.add(types.InlineKeyboardButton("🔙 بازگشت به لیست گروه‌ها", callback_data="pv_monitored_groups"))
            bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=markup)
            bot.answer_callback_query(call.id)

        elif data.startswith("pv_prt_"):
            _, _, chat_id, admin_id = data.split("_")
            add_protected_admin(int(chat_id), int(admin_id))
            bot.answer_callback_query(call.id, "به لیست سفید اضافه شد! ✅")
            bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
            handle_monitored_button(call.message)

        elif data.startswith("pv_unp_"):
            _, _, chat_id, admin_id = data.split("_")
            remove_protected_admin(int(chat_id), int(admin_id))
            bot.answer_callback_query(call.id, "از لیست سفید خارج شد! ⚠️")
            bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
            handle_monitored_button(call.message)

        elif data.startswith("pv_dem_"):
            _, _, chat_id, admin_id = data.split("_")
            demote_admin(int(chat_id), int(admin_id))
            log_action(int(chat_id), 'pv_demote', call.from_user.id, int(admin_id))
            bot.answer_callback_query(call.id, "ادمین خلع شد! 🔴", show_alert=True)
            handle_monitored_button(call.message)

        elif data.startswith('rem_'):
            _, chat_id, admin_id, flag_id = data.split('_')
            demote_admin(int(chat_id), int(admin_id))
            resolve_flag(int(flag_id), 'removed')
            bot.edit_message_text(f"✅ ادمین <code>{admin_id}</code> با موفقیت عزل شد.", call.message.chat.id, call.message.message_id)

        elif data.startswith('protect_'):
            _, chat_id, admin_id, flag_id = data.split('_')
            add_protected_admin(int(chat_id), int(admin_id))
            resolve_flag(int(flag_id), 'whitelisted')
            bot.edit_message_text(f"🛡 ادمین <code>{admin_id}</code> به لیست سفید اضافه شد.", call.message.chat.id, call.message.message_id)

        elif data.startswith('ign_'):
            flag_id = int(data.split('_')[1])
            resolve_flag(flag_id, 'ignored')
            bot.edit_message_text("✅ گزارش مختومه شد.", call.message.chat.id, call.message.message_id)

    except Exception as e:
        logging.error(f"Callback error: {e}")
        bot.answer_callback_query(call.id, f"خطا: {e}", show_alert=True)

# ---------------------------------------------------------
# روت‌های وب (Flask Endpoints برای ورسل)
# ---------------------------------------------------------
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    if path in ['api/webhook', 'webhook', 'api/index', '']:
        if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
            json_str = request.get_data().decode('utf-8')
            update = types.Update.de_json(json_str)
            bot.process_new_updates([update])
            return 'OK', 200
        elif request.method == 'GET' and path in ['', 'api/index']:
            return 'Bot is Running on Vercel!', 200

    if path in ['api/cron', 'cron']:
        secret = request.args.get('secret', '')
        if not hmac.compare_digest(secret, CRON_SECRET):
            return 'Forbidden', 403
        now = int(time.time())
        for g in get_all_groups():
            days = (now - g[4]) / 86400
            if days >= g[3]:
                warned_at = get_pending_warning(g[0])
                if not warned_at:
                    set_pending_warning(g[0], now)
                    try:
                        bot.send_message(g[0], WARNING_MESSAGE)
                    except Exception:
                        pass
        return 'Cron OK', 200

    return 'Not Found', 404

# تنظیم دستورات منوی رسمی تلگرام در هنگام اجرای برنامه
try:
    if BOT_TOKEN:
        bot.set_my_commands([
            types.BotCommand("start", "👑 باز کردن پنل مدیریت و کیبورد"),
            types.BotCommand("monitored", "👥 لیست افراد تحت پایش"),
            types.BotCommand("register", "➕ ثبت گروه در سیستم"),
            types.BotCommand("status", "📊 بررسی وضعیت امنیتی گروه")
        ])
except Exception:
    pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
