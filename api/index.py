import os
import time
import hmac
import html
import logging
from functools import wraps
from contextlib import contextmanager

import psycopg2
from psycopg2 import pool
from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify
import telebot
from telebot import types

# ---------------------------------------------------------
# تنظیمات لاگینگ و متغیرهای محیطی
# ---------------------------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BOT_TOKEN = os.environ['BOT_TOKEN']
SUPER_ADMIN_ID = int(os.environ['SUPER_ADMIN_ID'])
DATABASE_URL = os.environ['DATABASE_URL']
PANEL_PASSWORD = os.environ.get('PANEL_PASSWORD', 'admin123')
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())
CRON_SECRET = os.environ.get('CRON_SECRET', 'cron_secure_token')

WARNING_MESSAGE = """⚠️ <b>هشدار امنیتی ربات نظارت:</b>
مالک این گروه برای مدت طولانی هیچ فعالیتی نداشته است.
در صورتی که مالک ظرف ۲۴ ساعت آینده پیامی در گروه ارسال نکند، ادمین‌های غیرمحافظت‌شده به صورت خودکار عزل خواهند شد."""

bot = telebot.TeleBot(BOT_TOKEN, threaded=False, parse_mode='HTML')
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# ---------------------------------------------------------
# مدیریت پایگاه داده با سازگاری Serverless (Vercel)
# ---------------------------------------------------------
def create_pool():
    return pool.ThreadedConnectionPool(1, 10, DATABASE_URL, sslmode='require')

db_pool = create_pool()

@contextmanager
def get_db():
    global db_pool
    conn = None
    try:
        conn = db_pool.getconn()
        # تست زنده بودن اتصال (مخصوص سرورلس برای جلوگیری از Stale Connection)
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
    except Exception:
        if conn:
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
        if conn:
            db_pool.putconn(conn)

def init_db():
    """ساخت جداول پایگاه داده در صورت عدم وجود"""
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
    init_db()
except Exception as e:
    logging.error(f"Failed to init DB: {e}")

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
# توابع مدیریتی ربات تلگرام
# ---------------------------------------------------------
def get_group_owner(chat_id):
    """یافتن مالک گروه از تلگرام"""
    try:
        admins = bot.get_chat_administrators(chat_id)
        for a in admins:
            if a.status == 'creator':
                return a.user.id
    except Exception as e:
        logging.error(f"Error finding creator for {chat_id}: {e}")
    return None

def demote_admin(chat_id, admin_id):
    """سلب تمام دسترسی‌های ادمین خاطی"""
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
    """ارسال اعلان آنی به سوپرادمین"""
    try:
        info = bot.get_chat_member(chat_id, admin_id).user
        name = info.first_name or "ناشناس"
        username = f"@{info.username}" if info.username else "ندارد"
    except Exception:
        name = "ناشناس"
        username = "ندارد"

    status_str = "🔴 <b>ادمین به صورت خودکار عزل شد!</b>" if auto_demoted else "⚠️ <b>اقدام مورد نیاز سوپرادمین:</b>"

    text = (
        f"🚨 <b>هشدار امنیتی!</b>\n\n"
        f"{status_str}\n"
        f"📍 <b>گروه:</b> {html.escape(str(group_title))}\n"
        f"👤 <b>ادمین خاطی:</b> {html.escape(name)} ({username})\n"
        f"🆔 <b>شناسه عددی:</b> <code>{admin_id}</code>\n"
        f"💬 <b>علت:</b> {html.escape(reason)}\n"
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
            types.InlineKeyboardButton("🛡 افزودن به لیست سفید", callback_data=f"protect_{chat_id}_{admin_id}_{flag_id}"),
            types.InlineKeyboardButton("✅ تأیید", callback_data=f"ign_{flag_id}")
        )

    try:
        bot.send_message(SUPER_ADMIN_ID, text, reply_markup=markup)
    except Exception as e:
        logging.error(f"Failed to notify super admin: {e}")

# ---------------------------------------------------------
# منوی شیشه‌ای پیشرفته مخصوص پی‌وی (PV Menu Builders)
# ---------------------------------------------------------
def get_pv_main_menu():
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton("👥 افراد و ادمین‌های تحت پایش", callback_data="pv_monitored_groups"),
        types.InlineKeyboardButton("📋 لیست تمام گروه‌ها و وضعیت مالک", callback_data="pv_list_groups"),
        types.InlineKeyboardButton("🚨 هشدارهای فعال و گزارش‌ها", callback_data="pv_active_flags"),
        types.InlineKeyboardButton("🔄 بروزرسانی", callback_data="pv_refresh_main")
    )
    return markup

def get_pv_group_detail_markup(chat_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("👥 مشاهده ادمین‌های این گروه", callback_data=f"pv_admins_{chat_id}"),
        types.InlineKeyboardButton("🛡 ادمین‌های محافظت‌شده", callback_data=f"pv_protected_{chat_id}")
    )
    markup.add(
        types.InlineKeyboardButton("📜 مشاهده لاگ‌ها", callback_data=f"pv_logs_{chat_id}"),
        types.InlineKeyboardButton("🔒 تغییر قفل ارتقا", callback_data=f"pv_toggle_lock_{chat_id}")
    )
    markup.add(
        types.InlineKeyboardButton("🔙 بازگشت به لیست گروه‌ها", callback_data="pv_monitored_groups")
    )
    return markup

# ---------------------------------------------------------
# هندلرهای پیام‌های ربات تلگرام
# ---------------------------------------------------------
@bot.message_handler(commands=['start', 'panel', 'menu'])
def cmd_start(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        bot.reply_to(message, "⛔️ این ربات اختصاصی است و فقط به سوپرادمین پاسخ می‌دهد.")
        return

    if message.chat.type == 'private':
        text = (
            "👑 <b>پنل کنترل و پایش مرکزی ربات (مخصوص پی‌وی)</b>\n\n"
            "از منوی زیر می‌توانید وضعیت تمام گروه‌ها، ادمین‌های تحت نظارت و هشدارهای امنیتی را بررسی و مدیریت کنید:"
        )
        bot.send_message(message.chat.id, text, reply_markup=get_pv_main_menu())
    else:
        text = (
            "🤖 <b>ربات نظارت و امنیت گروه</b>\n\n"
            "▫️ <code>/register</code> - ثبت این گروه\n"
            "▫️ <code>/protect_admin &lt;ID&gt;</code> - محافظت از ادمین\n"
            "▫️ <code>/unprotect_admin &lt;ID&gt;</code> - لغو محافظت\n"
            "▫️ <code>/remove_admin &lt;ID&gt;</code> - عزل دستی ادمین\n"
            "▫️ <code>/status</code> - وضعیت امنیتی گروه\n\n"
            "💡 <i>برای مدیریت پیشرفته و کنترل تمام گروه‌ها به پی‌وی ربات مراجعه فرمایید.</i>"
        )
        bot.reply_to(message, text)

@bot.message_handler(commands=['monitored', 'monitored_list', 'list_admins', 'admins'])
def cmd_monitored_list(message):
    """دستور لیست افراد و ادمین‌های تحت پایش (هم در پی‌وی و هم در گروه)"""
    if message.from_user.id != SUPER_ADMIN_ID:
        return

    groups = get_all_groups()
    if not groups:
        bot.reply_to(message, "❌ هنوز هیچ گروهی در سیستم ثبت نشده است. ابتدا ربات را با دستور <code>/register</code> در گروه ثبت کنید.")
        return

    # اگر کاربر آیدی یک گروه را به عنوان آرگومان داده باشد
    target_chat_id = None
    parts = message.text.split()
    if len(parts) > 1:
        try:
            target_chat_id = int(parts[1])
        except ValueError:
            pass
    elif message.chat.type in ['group', 'supergroup']:
        target_chat_id = message.chat.id

    if target_chat_id:
        # نمایش لیست ادمین‌های یک گروه مشخص
        g = get_group(target_chat_id)
        if not g:
            bot.reply_to(message, f"❌ گروهی با شناسه <code>{target_chat_id}</code> پیدا نشد.")
            return
        
        protected = get_protected_admins(target_chat_id)
        owner_id = g[2]
        now = int(time.time())
        days_inactive = int((now - g[4]) / 86400)

        try:
            tg_admins = bot.get_chat_administrators(target_chat_id)
        except Exception as e:
            bot.reply_to(message, f"❌ خطا در دریافت ادمین‌ها از تلگرام: {e}")
            return

        bot_id = bot.get_me().id
        text = (
            f"👥 <b>لیست افراد تحت پایش گروه: {html.escape(g[1])}</b>\n"
            f"🆔 <code>{g[0]}</code> | 👑 مالک: <code>{owner_id}</code>\n"
            f"⏳ آخرین فعالیت مالک: <b>{days_inactive} روز پیش</b> (آستانه: {g[3]} روز)\n"
            f"━━━━━━━━━━━━━━━━━━━━\n\n"
        )

        for a in tg_admins:
            u = a.user
            if u.id == bot_id:
                continue
            name = html.escape(u.first_name or "ناشناس")
            
            if a.status == 'creator':
                role = "👑 <b>مالک اصلی</b>"
            elif u.id in protected:
                role = "🛡 <b>محافظت‌شده (لیست سفید)</b>"
            else:
                role = "⚠️ <b>تحت نظارت و آسیب‌پذیر</b>"

            text += f"▫️ {name} (<code>{u.id}</code>)\n   نقش: {role}\n\n"

        if message.chat.type == 'private':
            bot.send_message(message.chat.id, text, reply_markup=get_pv_group_detail_markup(target_chat_id))
        else:
            bot.reply_to(message, text)
        return

    # اگر در پی‌وی بدون آرگومان صدا زده شد: لیست تمام گروه‌ها با دکمه برای بررسی سریع
    markup = types.InlineKeyboardMarkup(row_width=1)
    text = "📋 <b>لیست گروه‌های تحت نظارت و پایش:</b>\nبرای مشاهده افراد و ادمین‌های هر گروه روی نام آن کلیک کنید:\n\n"
    
    now = int(time.time())
    for g in groups:
        chat_id, title, owner_id, threshold, last_act = g[0], g[1], g[2], g[3], g[4]
        days_inactive = int((now - last_act) / 86400)
        status_icon = "🔴" if days_inactive >= threshold else "🟢"
        text += f"{status_icon} <b>{html.escape(title)}</b>\n🆔 <code>{chat_id}</code> | خواب: {days_inactive} از {threshold} روز\n\n"
        markup.add(types.InlineKeyboardButton(f"👥 ادمین‌های {title}", callback_data=f"pv_admins_{chat_id}"))

    markup.add(types.InlineKeyboardButton("🔙 بازگشت به منوی اصلی", callback_data="pv_refresh_main"))
    bot.reply_to(message, text, reply_markup=markup)

@bot.message_handler(commands=['register'])
def register_group(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        bot.reply_to(message, "❌ فقط سوپرادمین اجازه ثبت دارد.")
        return
    chat = message.chat
    if chat.type not in ['group', 'supergroup']:
        bot.reply_to(message, "❌ این دستور را باید در داخل گروه ارسال کنید.")
        return

    try:
        bm = bot.get_chat_member(chat.id, bot.get_me().id)
        if bm.status != 'administrator' or not bm.can_promote_members or not bm.can_restrict_members:
            bot.reply_to(message, "❌ ربات باید در گروه دسترسی ادمین کامل (Promote & Restrict) داشته باشد.")
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
        if message.reply_to_message:
            target_id = message.reply_to_message.from_user.id
        elif len(parts) > 1:
            try:
                target_id = int(parts[1])
            except ValueError:
                pass
    else: # اگر در پی‌وی باشد
        if len(parts) >= 3:
            try:
                chat_id = int(parts[1])
                target_id = int(parts[2])
            except ValueError:
                pass

    if not chat_id or not target_id:
        bot.reply_to(message, "راهنما:\nدر گروه: <code>/protect_admin USER_ID</code> یا ریپلای روی ادمین\nدر پی‌وی: <code>/protect_admin CHAT_ID USER_ID</code>")
        return

    add_protected_admin(chat_id, target_id)
    bot.reply_to(message, f"🛡 کاربر <code>{target_id}</code> در گروه <code>{chat_id}</code> به لیست سفید و محافظت‌شده اضافه شد.")

@bot.message_handler(commands=['unprotect_admin'])
def cmd_unprotect_admin(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    parts = message.text.split()
    chat_id = None
    target_id = None

    if message.chat.type in ['group', 'supergroup']:
        chat_id = message.chat.id
        if message.reply_to_message:
            target_id = message.reply_to_message.from_user.id
        elif len(parts) > 1:
            try:
                target_id = int(parts[1])
            except ValueError:
                pass
    else:
        if len(parts) >= 3:
            try:
                chat_id = int(parts[1])
                target_id = int(parts[2])
            except ValueError:
                pass

    if not chat_id or not target_id:
        bot.reply_to(message, "راهنما:\nدر گروه: <code>/unprotect_admin USER_ID</code>\nدر پی‌وی: <code>/unprotect_admin CHAT_ID USER_ID</code>")
        return

    remove_protected_admin(chat_id, target_id)
    bot.reply_to(message, f"⚠️ کاربر <code>{target_id}</code> در گروه <code>{chat_id}</code> از لیست محافظت‌شده حذف شد.")

@bot.message_handler(commands=['remove_admin'])
def cmd_remove_admin(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    parts = message.text.split()
    chat_id = None
    target_id = None

    if message.chat.type in ['group', 'supergroup']:
        chat_id = message.chat.id
        if message.reply_to_message:
            target_id = message.reply_to_message.from_user.id
        elif len(parts) > 1:
            try:
                target_id = int(parts[1])
            except ValueError:
                pass
    else:
        if len(parts) >= 3:
            try:
                chat_id = int(parts[1])
                target_id = int(parts[2])
            except ValueError:
                pass

    if not chat_id or not target_id:
        bot.reply_to(message, "راهنما:\nدر گروه: <code>/remove_admin USER_ID</code> یا ریپلای روی پیام ادمین\nدر پی‌وی: <code>/remove_admin CHAT_ID USER_ID</code>")
        return

    if demote_admin(chat_id, target_id):
        log_action(chat_id, 'manual_demote', message.from_user.id, target_id, "عزل دستی توسط ادمین کل")
        bot.reply_to(message, f"✅ ادمین <code>{target_id}</code> در گروه <code>{chat_id}</code> با موفقیت عزل شد.")
    else:
        bot.reply_to(message, "❌ خطا در عزل ادمین. دسترسی‌های ربات در آن گروه را چک کنید.")

@bot.message_handler(commands=['status'])
def cmd_status(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    chat_id = message.chat.id if message.chat.type in ['group', 'supergroup'] else None
    parts = message.text.split()
    if len(parts) > 1:
        try:
            chat_id = int(parts[1])
        except ValueError:
            pass

    if not chat_id:
        if message.chat.type == 'private':
            cmd_monitored_list(message)
            return
        bot.reply_to(message, "شناسه گروه یافت نشد.")
        return

    group = get_group(chat_id)
    if not group:
        bot.reply_to(message, "گروه در سیستم ثبت نشده است.")
        return

    protected = get_protected_admins(chat_id)
    now = int(time.time())
    days_inactive = int((now - group[4]) / 86400)

    text = (
        f"📊 <b>وضعیت گروه: {html.escape(group[1])}</b>\n"
        f"🆔 شناسه گروه: <code>{group[0]}</code>\n"
        f"👑 شناسه مالک: <code>{group[2]}</code>\n"
        f"⏳ عدم فعالیت مالک: <b>{days_inactive} روز</b> (آستانه مجاز: {group[3]} روز)\n"
        f"🔒 قفل ارتقا: {'فعال ✅' if group[6] else 'غیرفعال ❌'}\n"
        f"🛡 تعداد ادمین‌های مصون: <b>{len(protected)} نفر</b>\n"
        f"⚡ آستانه بن سریع: {group[7]} بن در {group[9]} دقیقه"
    )
    bot.reply_to(message, text)

# ---------------------------------------------------------
# ثبت پیام‌ها برای تشخیص زنده بودن مالک
# ---------------------------------------------------------
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
            bot.send_message(message.chat.id, "✅ <b>فعالیت مالک تأیید شد.</b> فرآیند تعلیق و خلع ادمین‌ها لغو شد.")

# ---------------------------------------------------------
# هندلر رخدادهای اعضا و ادمین‌ها (Anti-Raid Core)
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

    if actor.id == target.id:
        return

    owner_id = group[2]
    strict_lock = group[6]
    ban_thresh = group[7]
    restrict_thresh = group[8]
    window_min = group[9]

    whitelist = get_protected_admins(chat_id) + [owner_id, SUPER_ADMIN_ID, bot.get_me().id]

    # 1. تشخیص بن مکرر (Mass Ban)
    if new_status in ['kicked', 'banned'] and old_status not in ['kicked', 'banned']:
        log_admin_action(chat_id, actor.id, 'ban', target.id)
        log_action(chat_id, 'ban', actor.id, target.id)

        if actor.id not in whitelist:
            count = count_recent_actions(chat_id, actor.id, 'ban', window_min)
            if count >= ban_thresh:
                demote_admin(chat_id, actor.id)
                reason = f"بن دسته‌جمعی خودکار ({count} بن در {window_min} دقیقه)"
                flag_id = add_flag(chat_id, actor.id, reason, 0)
                log_action(chat_id, 'auto_demote_ban', 0, actor.id, reason)
                notify_super_admin(chat_id, actor.id, group[1], reason, flag_id, auto_demoted=True)
                bot.send_message(chat_id, f"🚨 <b>هشدار:</b> دسترسی ادمین <code>{actor.id}</code> به دلیل بن‌های مکرر فوراً لغو شد.")

    # 2. تشخیص محدودسازی مکرر (Mass Restrict)
    elif new_status == 'restricted' and old_status != 'restricted':
        log_admin_action(chat_id, actor.id, 'restrict', target.id)
        log_action(chat_id, 'restrict', actor.id, target.id)

        if actor.id not in whitelist:
            count = count_recent_actions(chat_id, actor.id, 'restrict', window_min)
            if count >= restrict_thresh:
                demote_admin(chat_id, actor.id)
                reason = f"محدودسازی دسته‌جمعی خودکار ({count} میوت در {window_min} دقیقه)"
                flag_id = add_flag(chat_id, actor.id, reason, 0)
                log_action(chat_id, 'auto_demote_restrict', 0, actor.id, reason)
                notify_super_admin(chat_id, actor.id, group[1], reason, flag_id, auto_demoted=True)
                bot.send_message(chat_id, f"🚨 <b>هشدار:</b> دسترسی ادمین <code>{actor.id}</code> به دلیل محدودسازی بیش از حد اعضا سلب شد.")

    # 3. قفل ارتقای ادمین (Strict Promote Lock)
    elif new_status == 'administrator' and old_status != 'administrator':
        log_action(chat_id, 'promote', actor.id, target.id)

        if strict_lock and actor.id not in whitelist:
            demote_admin(chat_id, target.id)
            demote_admin(chat_id, actor.id)
            reason = f"ارتقای غیرمجاز کاربر {target.id} توسط ادمین عادی {actor.id}"
            flag_id = add_flag(chat_id, actor.id, reason, 0)
            log_action(chat_id, 'auto_demote_unauthorized_promoter', 0, actor.id, reason)
            notify_super_admin(chat_id, actor.id, group[1], reason, flag_id, auto_demoted=True)
            bot.send_message(chat_id, "⚠️ <b>قفل ارتقا:</b> ادمین‌های غیرمجاز خلع‌ید شدند.")

# ---------------------------------------------------------
# هندلرهای دکمه‌های شیشه‌ای (Callbacks)
# ---------------------------------------------------------
@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    if call.from_user.id != SUPER_ADMIN_ID:
        bot.answer_callback_query(call.id, "❌ دسترسی غیرمجاز.", show_alert=True)
        return

    data = call.data
    try:
        # برگشت به منوی اصلی پی‌وی
        if data == "pv_refresh_main":
            bot.edit_message_text(
                "👑 <b>پنل کنترل و پایش مرکزی ربات (مخصوص پی‌وی)</b>\nیک گزینه را انتخاب کنید:",
                call.message.chat.id, call.message.message_id,
                reply_markup=get_pv_main_menu()
            )
            bot.answer_callback_query(call.id)

        # لیست تمام گروه‌ها برای انتخاب افراد تحت پایش
        elif data == "pv_monitored_groups" or data == "pv_list_groups":
            groups = get_all_groups()
            if not groups:
                bot.answer_callback_query(call.id, "هیچ گروهی ثبت نشده است!", show_alert=True)
                return

            markup = types.InlineKeyboardMarkup(row_width=1)
            text = "👥 <b>انتخاب گروه جهت بررسی افراد تحت پایش و ادمین‌ها:</b>\n\n"
            now = int(time.time())
            for g in groups:
                days_inactive = int((now - g[4]) / 86400)
                icon = "🔴" if days_inactive >= g[3] else "🟢"
                text += f"{icon} <b>{html.escape(g[1])}</b> (خواب: {days_inactive} روز)\n"
                markup.add(types.InlineKeyboardButton(f"⚙️ مدیریت {g[1]}", callback_data=f"pv_detail_{g[0]}"))

            markup.add(types.InlineKeyboardButton("🔙 بازگشت", callback_data="pv_refresh_main"))
            bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=markup)
            bot.answer_callback_query(call.id)

        # جزییات یک گروه مشخص در پی‌وی
        elif data.startswith("pv_detail_"):
            chat_id = int(data.split("_")[2])
            g = get_group(chat_id)
            if not g:
                bot.answer_callback_query(call.id, "گروه یافت نشد!", show_alert=True)
                return

            now = int(time.time())
            days_inactive = int((now - g[4]) / 86400)
            protected_count = len(get_protected_admins(chat_id))

            text = (
                f"⚙️ <b>مرکز کنترل گروه: {html.escape(g[1])}</b>\n\n"
                f"🆔 شناسه گروه: <code>{g[0]}</code>\n"
                f"👑 مالک گروه: <code>{g[2]}</code>\n"
                f"⏳ آخرین فعالیت مالک: <b>{days_inactive} روز پیش</b> (آستانه: {g[3]} روز)\n"
                f"🔒 قفل ارتقای ادمین: {'فعال ✅' if g[6] else 'غیرفعال ❌'}\n"
                f"🛡 تعداد ادمین‌های مصون: <b>{protected_count} نفر</b>\n"
            )
            bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=get_pv_group_detail_markup(chat_id))
            bot.answer_callback_query(call.id)

        # لیست کامل تمام ادمین‌های یک گروه با دکمه‌های اقدام فوری
        elif data.startswith("pv_admins_"):
            chat_id = int(data.split("_")[2])
            g = get_group(chat_id)
            if not g:
                bot.answer_callback_query(call.id, "گروه یافت نشد.", show_alert=True)
                return

            protected = get_protected_admins(chat_id)
            owner_id = g[2]
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
                        types.InlineKeyboardButton(f"❌ لغو مصونیت {name[:12]}", callback_data=f"pv_unp_{chat_id}_{u.id}"),
                        types.InlineKeyboardButton(f"🛑 عزل {name[:12]}", callback_data=f"pv_dem_{chat_id}_{u.id}")
                    )
                else:
                    text += f"⚠️ <b>{name}</b> (<code>{u.id}</code>) - [تحت پایش و عادی]\n\n"
                    markup.add(
                        types.InlineKeyboardButton(f"🛡 افزودن به سفید {name[:12]}", callback_data=f"pv_prt_{chat_id}_{u.id}"),
                        types.InlineKeyboardButton(f"🛑 عزل {name[:12]}", callback_data=f"pv_dem_{chat_id}_{u.id}")
                    )

            markup.add(types.InlineKeyboardButton("🔙 بازگشت به گروه", callback_data=f"pv_detail_{chat_id}"))
            bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=markup)
            bot.answer_callback_query(call.id)

        # عملیات محافظت / لغو / عزل از منوی ادمین‌ها در پی‌وی
        elif data.startswith("pv_prt_"):
            _, _, chat_id, admin_id = data.split("_")
            add_protected_admin(int(chat_id), int(admin_id))
            bot.answer_callback_query(call.id, "به لیست سفید اضافه شد! ✅", show_alert=False)
            # بروزرسانی لیست
            handle_callback(type('obj', (object,), {'data': f'pv_admins_{chat_id}', 'from_user': call.from_user, 'message': call.message, 'id': call.id}))

        elif data.startswith("pv_unp_"):
            _, _, chat_id, admin_id = data.split("_")
            remove_protected_admin(int(chat_id), int(admin_id))
            bot.answer_callback_query(call.id, "از لیست سفید خارج شد! ⚠️", show_alert=False)
            handle_callback(type('obj', (object,), {'data': f'pv_admins_{chat_id}', 'from_user': call.from_user, 'message': call.message, 'id': call.id}))

        elif data.startswith("pv_dem_"):
            _, _, chat_id, admin_id = data.split("_")
            demote_admin(int(chat_id), int(admin_id))
            log_action(int(chat_id), 'pv_admin_demote', call.from_user.id, int(admin_id), "عزل از پنل پی‌وی")
            bot.answer_callback_query(call.id, "ادمین خلع‌ید شد! 🔴", show_alert=True)
            handle_callback(type('obj', (object,), {'data': f'pv_admins_{chat_id}', 'from_user': call.from_user, 'message': call.message, 'id': call.id}))

        # سوئیچ قفل ارتقای ادمین
        elif data.startswith("pv_toggle_lock_"):
            chat_id = int(data.split("_")[3])
            g = get_group(chat_id)
            if g:
                new_lock = not g[6]
                update_group_settings(chat_id, g[3], new_lock, g[7], g[8], g[9])
                bot.answer_callback_query(call.id, f"قفل ارتقا: {'فعال شد ✅' if new_lock else 'غیرفعال شد ❌'}")
                handle_callback(type('obj', (object,), {'data': f'pv_detail_{chat_id}', 'from_user': call.from_user, 'message': call.message, 'id': call.id}))

        # گزارش‌ها و هشدارهای فعال
        elif data == "pv_active_flags":
            flags = get_flags('pending')
            if not flags:
                bot.answer_callback_query(call.id, "هیچ گزارش و هشدار معلقی وجود ندارد! ✨", show_alert=True)
                return
            text = "🚨 <b>هشدارهای امنیتی فعال:</b>\n\n"
            for f in flags[:10]:
                text += f"▫️ ادمین <code>{f[2]}</code> در گروه <code>{f[1]}</code>\nعلت: {html.escape(f[3])}\n\n"
            bot.send_message(call.message.chat.id, text)
            bot.answer_callback_query(call.id)

        # سایر کلیدها
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
# روت‌های وب (Flask Endpoints سازگار با Vercel)
# ---------------------------------------------------------
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    # دریافت وب‌هوک تلگرام
    if path in ['api/webhook', 'webhook', 'api/index']:
        if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
            json_str = request.get_data().decode('utf-8')
            update = types.Update.de_json(json_str)
            bot.process_new_updates([update])
            return 'OK', 200
        return 'Webhook is active', 200

    # کران جاب
    if path in ['api/cron', 'cron']:
        secret = request.args.get('secret', '')
        if not hmac.compare_digest(secret, CRON_SECRET):
            return 'Forbidden', 403

        now = int(time.time())
        for g in get_all_groups():
            chat_id, title, owner_id, threshold, last_activity = g[0], g[1], g[2], g[3], g[4]
            days_inactive = (now - last_activity) / 86400

            if days_inactive >= threshold:
                warned_at = get_pending_warning(chat_id)
                if not warned_at:
                    set_pending_warning(chat_id, now)
                    try:
                        bot.send_message(chat_id, WARNING_MESSAGE)
                    except Exception:
                        pass
                elif now - warned_at >= 86400:
                    purge_unprotected_admins(chat_id)
                    clear_pending_warning(chat_id)
        return 'Cron OK', 200

    # در صورت باز شدن ریشه توسط مرورگر
    if path == '' and request.method == 'GET':
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return redirect(url_for('dashboard'))

    return 'Not Found', 404

def purge_unprotected_admins(chat_id):
    group = get_group(chat_id)
    if not group:
        return
    owner_id = group[2]
    protected = get_protected_admins(chat_id) + [owner_id, SUPER_ADMIN_ID, bot.get_me().id]
    try:
        admins = bot.get_chat_administrators(chat_id)
    except Exception:
        return

    removed = []
    for admin in admins:
        if admin.status == 'creator' or admin.user.id in protected:
            continue
        if demote_admin(chat_id, admin.user.id):
            removed.append(admin.user.id)
            log_action(chat_id, 'inactivity_purge', 0, admin.user.id, "حذف به دلیل عدم فعالیت مالک")

    if removed:
        bot.send_message(chat_id, f"🛡 <b>پاکسازی امنیتی:</b> تعداد {len(removed)} ادمین به دلیل عدم حضور مالک عزل شدند.")

# ---------------------------------------------------------
# داشبورد وب (Web Panel)
# ---------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

STYLE = """
<style>
* { box-sizing: border-box; font-family: Tahoma, sans-serif; }
body { background: #f1f5f9; margin: 0; padding: 0; direction: rtl; color: #1e293b; }
nav { background: #0f172a; padding: 15px 30px; display: flex; justify-content: space-between; }
nav a { color: #fff; text-decoration: none; margin-left: 20px; font-size: 14px; }
.container { max-width: 1000px; margin: 30px auto; background: #fff; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
table { width: 100%; border-collapse: collapse; margin-top: 15px; }
th, td { padding: 10px 14px; border-bottom: 1px solid #e2e8f0; text-align: right; }
th { background: #f8fafc; color: #475569; }
.btn { padding: 6px 12px; border: none; border-radius: 5px; cursor: pointer; color: #fff; text-decoration: none; font-size: 13px; display: inline-block; }
.btn-blue { background: #0284c7; }
.btn-red { background: #ef4444; }
.btn-green { background: #16a34a; }
.badge { padding: 4px 8px; border-radius: 12px; font-size: 12px; color: #fff; }
.bg-red { background: #ef4444; }
.bg-green { background: #16a34a; }
input { padding: 8px; border: 1px solid #cbd5e1; border-radius: 5px; }
</style>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    err = ""
    if request.method == 'POST':
        if hmac.compare_digest(request.form.get('password', ''), PANEL_PASSWORD):
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        err = "رمز عبور نادرست است."
    return render_template_string(STYLE + f"""
    <div class="container" style="max-width: 350px; margin-top: 80px; text-align: center;">
        <h2>ورود به پنل مدیریت</h2>
        {'<p style="color:red">'+err+'</p>' if err else ''}
        <form method="post">
            <input type="password" name="password" placeholder="رمز پنل..." required style="width: 100%; margin-bottom: 15px;"><br>
            <button class="btn btn-blue" style="width: 100%; padding: 10px;">ورود</button>
        </form>
    </div>
    """)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    groups = get_all_groups()
    now = int(time.time())
    rows = ""
    for g in groups:
        days = int((now - g[4]) / 86400)
        badge = f'<span class="badge bg-red">{days} روز خواب</span>' if days >= g[3] else f'<span class="badge bg-green">{days} روز (فعال)</span>'
        rows += f"<tr><td><b>{html.escape(g[1])}</b></td><td><code>{g[2]}</code></td><td>{badge}</td><td><a href='/group/{g[0]}' class='btn btn-blue'>مدیریت</a></td></tr>"

    html_content = f"""
    {STYLE}
    <nav><div><a href="/dashboard">📊 داشبورد</a><a href="/flags">🚨 گزارش‌ها</a></div><div><a href="/logout" style="color:#f87171;">خروج</a></div></nav>
    <div class="container">
        <h2>📊 وضعیت گروه‌های تحت نظارت</h2>
        <table>
            <tr><th>نام گروه</th><th>مالک</th><th>وضعیت</th><th>عملیات</th></tr>
            {rows or '<tr><td colspan="4" style="text-align:center;">هیچ گروهی ثبت نشده است.</td></tr>'}
        </table>
    </div>
    """
    return html_content

@app.route('/group/<int:chat_id>')
@login_required
def group_detail(chat_id):
    group = get_group(chat_id)
    if not group:
        return "گروه یافت نشد", 404

    protected = get_protected_admins(chat_id)
    try:
        admins = bot.get_chat_administrators(chat_id)
    except Exception:
        admins = []

    admin_rows = ""
    for a in admins:
        if a.user.id == bot.get_me().id:
            continue
        if a.status == 'creator':
            admin_rows += f"<tr><td>👑 {html.escape(a.user.first_name)}</td><td><code>{a.user.id}</code></td><td>مالک</td><td>-</td></tr>"
            continue
        is_p = a.user.id in protected
        btn_prot = f"<form method='post' action='/group/{chat_id}/toggle_p/{a.user.id}' style='display:inline;'><button class='btn {'btn-green' if is_p else 'btn-blue'}'>{'محافظت‌شده ✅' if is_p else 'محافظت 🛡'}</button></form>"
        btn_demote = f"<form method='post' action='/group/{chat_id}/demote/{a.user.id}' onsubmit='return confirm(\"عزل شود؟\");' style='display:inline;'><button class='btn btn-red'>عزل ❌</button></form>"
        admin_rows += f"<tr><td>{html.escape(a.user.first_name)}</td><td><code>{a.user.id}</code></td><td>{btn_prot}</td><td>{btn_demote}</td></tr>"

    return render_template_string(STYLE + f"""
    <nav><div><a href="/dashboard">📊 داشبورد</a></div><div><a href="/logout">خروج</a></div></nav>
    <div class="container">
        <h2>مدیریت گروه: {html.escape(group[1])}</h2>
        <h3>👥 لیست ادمین‌ها</h3>
        <table><tr><th>نام ادمین</th><th>شناسه</th><th>حفاظت</th><th>عملیات</th></tr>{admin_rows}</table>
    </div>
    """)

@app.route('/group/<int:chat_id>/toggle_p/<int:admin_id>', methods=['POST'])
@login_required
def toggle_protection_web(chat_id, admin_id):
    if admin_id in get_protected_admins(chat_id):
        remove_protected_admin(chat_id, admin_id)
    else:
        add_protected_admin(chat_id, admin_id)
    return redirect(f"/group/{chat_id}")

@app.route('/group/<int:chat_id>/demote/<int:admin_id>', methods=['POST'])
@login_required
def demote_web(chat_id, admin_id):
    demote_admin(chat_id, admin_id)
    log_action(chat_id, 'web_demote', 0, admin_id)
    return redirect(f"/group/{chat_id}")

@app.route('/flags')
@login_required
def flags_view():
    flags = get_flags('pending')
    rows = ""
    for f in flags:
        rows += f"<tr><td>{f[1]}</td><td>{f[2]}</td><td>{html.escape(f[3])}</td><td><form method='post' action='/flags/{f[0]}/resolve' style='display:inline;'><button class='btn btn-green'>بستن ✅</button></form></td></tr>"
    return render_template_string(STYLE + f"""
    <nav><div><a href="/dashboard">📊 داشبورد</a><a href="/flags">🚨 گزارش‌ها</a></div><div><a href="/logout">خروج</a></div></nav>
    <div class="container">
        <h2>🚨 گزارش‌های بررسی‌نشده</h2>
        <table><tr><th>گروه</th><th>ادمین</th><th>علت</th><th>عملیات</th></tr>{rows or '<tr><td colspan="4" style="text-align:center;">هیچ گزارشی وجود ندارد.</td></tr>'}</table>
    </div>
    """)

@app.route('/flags/<int:flag_id>/resolve', methods=['POST'])
@login_required
def resolve_flag_route(flag_id):
    resolve_flag(flag_id, 'resolved')
    return redirect('/flags')

# ---------------------------------------------------------
# راه‌اندازی لوکال
# ---------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
