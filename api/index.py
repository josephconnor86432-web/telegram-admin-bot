import os
import time
from functools import wraps

import psycopg2
from flask import Flask, request, session, redirect, url_for, render_template_string
import telebot
from telebot import types

BOT_TOKEN = os.environ['BOT_TOKEN']
SUPER_ADMIN_ID = int(os.environ['SUPER_ADMIN_ID'])
DATABASE_URL = os.environ['DATABASE_URL']
PANEL_PASSWORD = os.environ['PANEL_PASSWORD']
FLASK_SECRET_KEY = os.environ['FLASK_SECRET_KEY']
CRON_SECRET = os.environ['CRON_SECRET']

MASS_BAN_THRESHOLD = 8
MASS_BAN_WINDOW_MIN = 10
MASS_RESTRICT_THRESHOLD = 10
MASS_RESTRICT_WINDOW_MIN = 10

WARNING_MESSAGE = """⚠️ هشدار: مالک این گروه برای مدت طولانی فعالیتی نداشته است.
ادمین‌های غیرمحافظت‌شده ظرف ۲۴ ساعت آینده حذف خواهند شد،
مگر اینکه مالک فعالیت کند."""

bot = telebot.TeleBot(BOT_TOKEN, threaded=False)
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY


def get_conn():
    return psycopg2.connect(DATABASE_URL, sslmode='require')


def add_group(chat_id, title, owner_id, chat_type, threshold=30):
    conn = get_conn(); c = conn.cursor()
    c.execute("""INSERT INTO groups (chat_id, chat_title, owner_id, threshold_days, last_owner_activity, chat_type)
                 VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (chat_id) DO NOTHING""",
              (chat_id, title, owner_id, threshold, int(time.time()), chat_type))
    conn.commit(); c.close(); conn.close()

def update_owner_activity(chat_id, ts):
    conn = get_conn(); c = conn.cursor()
    c.execute("UPDATE groups SET last_owner_activity=%s WHERE chat_id=%s", (ts, chat_id))
    conn.commit(); c.close(); conn.close()

def get_all_groups():
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM groups")
    rows = c.fetchall(); c.close(); conn.close()
    return rows

def get_group(chat_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM groups WHERE chat_id=%s", (chat_id,))
    row = c.fetchone(); c.close(); conn.close()
    return row

def set_threshold(chat_id, days):
    conn = get_conn(); c = conn.cursor()
    c.execute("UPDATE groups SET threshold_days=%s WHERE chat_id=%s", (days, chat_id))
    conn.commit(); c.close(); conn.close()

def add_protected_admin(chat_id, admin_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("""INSERT INTO protected_admins (chat_id, admin_id) VALUES (%s,%s)
                 ON CONFLICT DO NOTHING""", (chat_id, admin_id))
    conn.commit(); c.close(); conn.close()

def remove_protected_admin(chat_id, admin_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("DELETE FROM protected_admins WHERE chat_id=%s AND admin_id=%s", (chat_id, admin_id))
    conn.commit(); c.close(); conn.close()

def get_protected_admins(chat_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT admin_id FROM protected_admins WHERE chat_id=%s", (chat_id,))
    rows = [r[0] for r in c.fetchall()]; c.close(); conn.close()
    return rows

def log_action(chat_id, action, actor_id, target_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("""INSERT INTO action_log (chat_id, action, actor_id, target_id, timestamp)
                 VALUES (%s,%s,%s,%s,%s)""", (chat_id, action, actor_id, target_id, int(time.time())))
    conn.commit(); c.close(); conn.close()

def get_action_log(chat_id, limit=30):
    conn = get_conn(); c = conn.cursor()
    c.execute("""SELECT action, actor_id, target_id, timestamp FROM action_log
                 WHERE chat_id=%s ORDER BY timestamp DESC LIMIT %s""", (chat_id, limit))
    rows = c.fetchall(); c.close(); conn.close()
    return rows

def log_admin_action(chat_id, admin_id, action_type, target_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("""INSERT INTO admin_actions (chat_id, admin_id, action_type, target_id, timestamp)
                 VALUES (%s,%s,%s,%s,%s)""", (chat_id, admin_id, action_type, target_id, int(time.time())))
    conn.commit(); c.close(); conn.close()

def count_recent_actions(chat_id, admin_id, action_type, window_minutes):
    since = int(time.time()) - window_minutes * 60
    conn = get_conn(); c = conn.cursor()
    c.execute("""SELECT COUNT(*) FROM admin_actions
                 WHERE chat_id=%s AND admin_id=%s AND action_type=%s AND timestamp>=%s""",
              (chat_id, admin_id, action_type, since))
    count = c.fetchone()[0]; c.close(); conn.close()
    return count

def add_flag(chat_id, admin_id, reason, reported_by):
    conn = get_conn(); c = conn.cursor()
    c.execute("""INSERT INTO flags (chat_id, admin_id, reason, reported_by, timestamp)
                 VALUES (%s,%s,%s,%s,%s) RETURNING id""",
              (chat_id, admin_id, reason, reported_by, int(time.time())))
    flag_id = c.fetchone()[0]
    conn.commit(); c.close(); conn.close()
    return flag_id

def get_flags(status='pending'):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM flags WHERE status=%s ORDER BY timestamp DESC", (status,))
    rows = c.fetchall(); c.close(); conn.close()
    return rows

def resolve_flag(flag_id, status='resolved'):
    conn = get_conn(); c = conn.cursor()
    c.execute("UPDATE flags SET status=%s WHERE id=%s", (status, flag_id))
    conn.commit(); c.close(); conn.close()

def get_flag(flag_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM flags WHERE id=%s", (flag_id,))
    row = c.fetchone(); c.close(); conn.close()
    return row

def get_pending_warning(chat_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT warned_at FROM pending_warnings WHERE chat_id=%s", (chat_id,))
    row = c.fetchone(); c.close(); conn.close()
    return row[0] if row else None

def set_pending_warning(chat_id, ts):
    conn = get_conn(); c = conn.cursor()
    c.execute("""INSERT INTO pending_warnings (chat_id, warned_at) VALUES (%s,%s)
                 ON CONFLICT (chat_id) DO UPDATE SET warned_at=%s""", (chat_id, ts, ts))
    conn.commit(); c.close(); conn.close()

def clear_pending_warning(chat_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("DELETE FROM pending_warnings WHERE chat_id=%s", (chat_id,))
    conn.commit(); c.close(); conn.close()


def demote_admin(chat_id, admin_id):
    bot.promote_chat_member(
        chat_id, admin_id,
        can_change_info=False, can_delete_messages=False,
        can_invite_users=False, can_restrict_members=False,
        can_pin_messages=False, can_promote_members=False,
        can_manage_chat=False, can_manage_video_chats=False,
        can_post_messages=False, can_edit_messages=False
    )

def notify_super_admin(chat_id, admin_id, group_title, reason, flag_id):
    try:
        info = bot.get_chat_member(chat_id, admin_id).user
        name = info.first_name or str(admin_id)
    except Exception:
        name = str(admin_id)

    text = f"🚨 رفتار مشکوک شناسایی شد!\n\nگروه: {group_title}\nادمین: {name} ({admin_id})\nدلیل: {reason}"
    markup = types.InlineKeyboardMarkup()
    markup.add(
        types.InlineKeyboardButton("🔴 حذف فوری", callback_data=f"remove_{chat_id}_{admin_id}_{flag_id}"),
        types.InlineKeyboardButton("✅ نادیده بگیر", callback_data=f"ignore_{flag_id}")
    )
    try:
        bot.send_message(SUPER_ADMIN_ID, text, reply_markup=markup)
    except Exception as e:
        print(f"خطا در اطلاع‌رسانی: {e}")

def check_mass_ban(chat_id, admin_id, group_title):
    count = count_recent_actions(chat_id, admin_id, 'ban', MASS_BAN_WINDOW_MIN)
    if count >= MASS_BAN_THRESHOLD:
        reason = f"بن دسته‌جمعی: {count} بن در {MASS_BAN_WINDOW_MIN} دقیقه"
        flag_id = add_flag(chat_id, admin_id, reason, 0)
        notify_super_admin(chat_id, admin_id, group_title, reason, flag_id)

def check_mass_restrict(chat_id, admin_id, group_title):
    count = count_recent_actions(chat_id, admin_id, 'restrict', MASS_RESTRICT_WINDOW_MIN)
    if count >= MASS_RESTRICT_THRESHOLD:
        reason = f"محدودسازی دسته‌جمعی: {count} مورد در {MASS_RESTRICT_WINDOW_MIN} دقیقه"
        flag_id = add_flag(chat_id, admin_id, reason, 0)
        notify_super_admin(chat_id, admin_id, group_title, reason, flag_id)

@bot.message_handler(commands=['register'])
def register_group(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    chat = message.chat
    try:
        bm = bot.get_chat_member(chat.id, bot.get_me().id)
        if bm.status != 'administrator':
            bot.reply_to(message, "❌ ابتدا ربات را ادمین کامل کنید.")
            return
    except Exception as e:
        bot.reply_to(message, f"خطا: {e}")
        return
    add_group(chat.id, chat.title, SUPER_ADMIN_ID, chat.type)
    bot.reply_to(message, f"✅ گروه '{chat.title}' ثبت شد.\nChat ID: {chat.id}")

@bot.message_handler(commands=['set_threshold'])
def cmd_set_threshold(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    try:
        days = int(message.text.split()[1])
        set_threshold(message.chat.id, days)
        bot.reply_to(message, f"✅ آستانه به {days} روز تغییر یافت.")
    except Exception:
        bot.reply_to(message, "استفاده: /set_threshold 30")

@bot.message_handler(commands=['protect_admin'])
def cmd_protect_admin(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        return
    try:
        target_id = int(message.text.split()[1])
        add_protected_admin(message.chat.id, target_id)
        bot.reply_to(message, f"✅ کاربر {target_id} محافظت شد.")
    except Exception:
        bot.reply_to(message, "استفاده: /protect_admin USER_ID")

@bot.message_handler(commands=['remove_admin'])
def cmd_remove_admin(message):
    if message.from_user.id != SUPER_ADMIN_ID:
        bot.reply_to(message, "❌ دسترسی ندارید.")
        return
    target_id = None
    if message.reply_to_message:
        target_id = message.reply_to_message.from_user.id
    else:
        try:
            target_id = int(message.text.split()[1])
        except Exception:
            bot.reply_to(message, "روی پیام ادمین ریپلای کنید یا /remove_admin USER_ID")
            return
    try:
        demote_admin(message.chat.id, target_id)
        log_action(message.chat.id, 'manual_remove', message.from_user.id, target_id)
        bot.reply_to(message, f"✅ ادمین {target_id} حذف شد.")
    except Exception as e:
        bot.reply_to(message, f"خطا: {e}")

@bot.message_handler(commands=['report_admin'])
def cmd_report_admin(message):
    if not message.reply_to_message:
        bot.reply_to(message, "این دستور را روی پیام ادمین خاطی ریپلای کنید.")
        return
    target = message.reply_to_message.from_user
    admins = bot.get_chat_administrators(message.chat.id)
    if target.id not in [a.user.id for a in admins]:
        bot.reply_to(message, "کاربر موردنظر ادمین نیست.")
        return
    reason = "گزارش عضو گروه"
    if len(message.text.split()) > 1:
        reason = message.text.split(maxsplit=1)[1]
    group = get_group(message.chat.id)
    flag_id = add_flag(message.chat.id, target.id, reason, message.from_user.id)
    notify_super_admin(message.chat.id, target.id, group[1] if group else "نامشخص", reason, flag_id)
    bot.reply_to(message, "✅ گزارش شما ثبت شد.")

@bot.message_handler(func=lambda m: True, content_types=['text', 'photo', 'video', 'sticker', 'document', 'voice'])
def track_owner_activity(message):
    group = get_group(message.chat.id)
    if not group:
        return
    owner_id = group[2]
    if message.from_user and message.from_user.id == owner_id:
        update_owner_activity(message.chat.id, int(time.time()))
        if get_pending_warning(message.chat.id):
            clear_pending_warning(message.chat.id)
            bot.send_message(message.chat.id, "✅ مالک فعالیت کرد. عملیات حذف لغو شد.")

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

    if new_status == 'kicked' and old_status != 'kicked':
        log_admin_action(chat_id, actor.id, 'ban', target.id)
        log_action(chat_id, 'ban', actor.id, target.id)
        check_mass_ban(chat_id, actor.id, group[1])
    elif new_status == 'restricted' and old_status != 'restricted':
        log_admin_action(chat_id, actor.id, 'restrict', target.id)
        log_action(chat_id, 'restrict', actor.id, target.id)
        check_mass_restrict(chat_id, actor.id, group[1])
    elif new_status == 'administrator' and old_status != 'administrator':
        log_action(chat_id, 'promote', actor.id, target.id)
        protected = get_protected_admins(chat_id) + [group[2], SUPER_ADMIN_ID]
        if actor.id not in protected:
            reason = f"ارتقای غیرمجاز کاربر {target.id} به ادمین"
            flag_id = add_flag(chat_id, actor.id, reason, actor.id)
            notify_super_admin(chat_id, actor.id, group[1], reason, flag_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith(('remove_', 'ignore_')))
def handle_callback(call):
    if call.from_user.id != SUPER_ADMIN_ID:
        bot.answer_callback_query(call.id, "دسترسی ندارید.")
        return
    if call.data.startswith('remove_'):
        _, chat_id, admin_id, flag_id = call.data.split('_')
        chat_id, admin_id, flag_id = int(chat_id), int(admin_id), int(flag_id)
        try:
            demote_admin(chat_id, admin_id)
            resolve_flag(flag_id, 'removed')
            log_action(chat_id, 'manual_remove', call.from_user.id, admin_id)
            bot.edit_message_text("✅ ادمین حذف شد.", call.message.chat.id, call.message.message_id)
            bot.send_message(chat_id, "⚠️ یک مدیر به دلیل رفتار نامناسب حذف شد.")
        except Exception as e:
            bot.answer_callback_query(call.id, f"خطا: {e}")
    else:
        flag_id = int(call.data.split('_')[1])
        resolve_flag(flag_id, 'ignored')
        bot.edit_message_text("گزارش نادیده گرفته شد.", call.message.chat.id, call.message.message_id)


@app.route('/api/webhook', methods=['POST'])
def webhook():
    update = types.Update.de_json(request.get_data().decode('utf-8'))
    bot.process_new_updates([update])
    return 'OK', 200

@app.route('/api/cron', methods=['GET'])
def cron_check():
    if request.args.get('secret') != CRON_SECRET:
        return 'Forbidden', 403

    now = int(time.time())
    for g in get_all_groups():
        chat_id, title, owner_id, threshold, last_activity, chat_type = g
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
                remove_old_admins(chat_id)
                clear_pending_warning(chat_id)

    return 'OK', 200

def remove_old_admins(chat_id):
    group = get_group(chat_id)
    if not group:
        return
    owner_id = group[2]
    protected = get_protected_admins(chat_id) + [owner_id, SUPER_ADMIN_ID]
    admins = bot.get_chat_administrators(chat_id)
    bot_id = bot.get_me().id
    removed = []
    for admin in admins:
        if admin.status == 'creator' or admin.user.id in protected + [bot_id]:
            continue
        try:
            demote_admin(chat_id, admin.user.id)
            removed.append(admin.user.id)
            log_action(chat_id, 'inactivity_remove', 0, admin.user.id)
        except Exception as e:
            print(f"خطا: {e}")
    if removed:
        bot.send_message(chat_id, f"✅ {len(removed)} ادمین به دلیل عدم فعالیت مالک حذف شدند.")


 





def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

STYLE = "<style>body{font-family:Tahoma;direction:rtl;background:#f4f4f9;margin:0}.container{max-width:900px;margin:30px auto;background:#fff;padding:25px;border-radius:10px;box-shadow:0 0 10px #ddd}table{width:100%;border-collapse:collapse;margin-top:15px}th,td{padding:10px;border-bottom:1px solid #eee;text-align:right}.btn{padding:6px 14px;border:none;border-radius:5px;cursor:pointer;color:#fff}.btn-red{background:#e74c3c}.btn-green{background:#27ae60}.btn-blue{background:#2980b9;text-decoration:none}.badge-red{background:#e74c3c;color:#fff;padding:3px 8px;border-radius:12px;font-size:12px}.badge-green{background:#27ae60;color:#fff;padding:3px 8px;border-radius:12px;font-size:12px}input{padding:8px;border:1px solid #ccc;border-radius:5px}nav{background:#2c3e50;padding:15px}nav a{color:#fff;margin-left:20px;text-decoration:none}</style>"
NAV = '<nav><a href="/">داشبورد</a><a href="/flags">گزارش‌ها</a><a href="/logout">خروج</a></nav>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form.get('password') == PANEL_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        error = "رمز اشتباه است"
    err_html = "<p style='color:red'>" + error + "</p>" if error else ""
    return render_template_string(STYLE + """
    <div class="container" style="max-width:350px;text-align:center">
    <h2>ورود به پنل</h2>
    <form method="post">
    <input type="password" name="password" placeholder="رمز عبور" required><br><br>
    <button class="btn btn-blue">ورود</button>
    </form>""" + err_html + "</div>")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    groups = get_all_groups()
    now = int(time.time())
    rows = ""
    for g in groups:
        chat_id, title, owner_id, threshold, last_activity, chat_type = g
        days = int((now - last_activity) / 86400)
        if days >= threshold:
            badge = '<span class="badge-red">warn ' + str(days) + ' days</span>'
        else:
            badge = '<span class="badge-green">ok ' + str(days) + ' days</span>'
        rows += "<tr><td>" + str(title) + "</td><td>" + str(chat_type) + "</td><td>" + badge + "</td><td><a class='btn btn-blue' href='/group/" + str(chat_id) + "'>مدیریت</a></td></tr>"
    body = "<div class='container'><h1>Dashboard</h1><table><tr><th>Title</th><th>Type</th><th>Status</th><th>Action</th></tr>" + (rows or "<tr><td colspan=4>No groups</td></tr>") + "</table></div>"
    return render_template_string(STYLE + NAV + body)

@app.route('/group/<int:chat_id>')
@login_required
def group_detail(chat_id):
    group = get_group(chat_id)
    if not group:
        return "Not found", 404
    protected = get_protected_admins(chat_id)
    try:
        admins = bot.get_chat_administrators(chat_id)
    except Exception:
        admins = []
    admin_rows = ""
    for a in admins:
        if a.status == 'creator':
            continue
        is_p = a.user.id in protected
        if is_p:
            pbtn = "<form method='post' action='/group/" + str(chat_id) + "/unprotect/" + str(a.user.id) + "' style='display:inline'><button class='btn btn-green'>Protected</button></form>"
        else:
            pbtn = "<form method='post' action='/group/" + str(chat_id) + "/protect/" + str(a.user.id) + "' style='display:inline'><button class='btn btn-blue'>Protect</button></form>"
        admin_rows += "<tr><td>" + str(a.user.first_name) + " (" + str(a.user.id) + ")</td><td>" + pbtn + "</td><td><form method='post' action='/group/" + str(chat_id) + "/remove/" + str(a.user.id) + "' onsubmit='return confirm(\\'Sure?\\')' style='display:inline'><button class='btn btn-red'>Remove</button></form></td></tr>"
    log_rows = ""
    for action, actor, target, ts in get_action_log(chat_id, 30):
        t = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
        log_rows += "<tr><td>" + str(action) + "</td><td>" + str(actor) + "</td><td>" + str(target) + "</td><td>" + t + "</td></tr>"
    body = "<div class='container'><h1>Group: " + str(group[1]) + "</h1>"
    body += "<h2>Settings</h2><form method='post' action='/group/" + str(chat_id) + "/settings'>Threshold (days): <input type='number' name='threshold' value='" + str(group[3]) + "'><button class='btn btn-blue'>Save</button></form>"
    body += "<h2>Admins</h2><table><tr><th>Admin</th><th>Protection</th><th>Action</th></tr>" + (admin_rows or "<tr><td colspan=3>None</td></tr>") + "</table>"
    body += "<h2>Log</h2><table><tr><th>Action</th><th>Actor</th><th>Target</th><th>Time</th></tr>" + (log_rows or "<tr><td colspan=4>None</td></tr>") + "</table></div>"
    return render_template_string(STYLE + NAV + body)

@app.route('/group/<int:chat_id>/remove/<int:admin_id>', methods=['POST'])
@login_required
def remove_admin_panel(chat_id, admin_id):
    try:
        demote_admin(chat_id, admin_id)
        log_action(chat_id, 'panel_remove', 0, admin_id)
        bot.send_message(chat_id, "Warning: an admin was removed via panel.")
    except Exception as e:
        print(e)
    return redirect(url_for('group_detail', chat_id=chat_id))

@app.route('/group/<int:chat_id>/protect/<int:admin_id>', methods=['POST'])
@login_required
def protect_admin_panel(chat_id, admin_id):
    add_protected_admin(chat_id, admin_id)
    return redirect(url_for('group_detail', chat_id=chat_id))

@app.route('/group/<int:chat_id>/unprotect/<int:admin_id>', methods=['POST'])
@login_required
def unprotect_admin_panel(chat_id, admin_id):
    remove_protected_admin(chat_id, admin_id)
    return redirect(url_for('group_detail', chat_id=chat_id))

@app.route('/group/<int:chat_id>/settings', methods=['POST'])
@login_required
def update_settings(chat_id):
    set_threshold(chat_id, int(request.form.get('threshold', 30)))
    return redirect(url_for('group_detail', chat_id=chat_id))

@app.route('/flags')
@login_required
def flags_page():
    flags = get_flags('pending')
    rows = ""
    for f in flags:
        fid, chat_id, admin_id, reason, reported_by, status, ts = f
        group = get_group(chat_id)
        t = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
        gtitle = group[1] if group else chat_id
        rows += "<tr><td>" + str(gtitle) + "</td><td>" + str(admin_id) + "</td><td>" + str(reason) + "</td><td>" + t + "</td><td><form method='post' action='/flags/" + str(fid) + "/remove' style='display:inline'><button class='btn btn-red'>Remove</button></form><form method='post' action='/flags/" + str(fid) + "/ignore' style='display:inline'><button class='btn btn-green'>Ignore</button></form></td></tr>"
    body = "<div class='container'><h1>Flags</h1><table><tr><th>Group</th><th>Admin</th><th>Reason</th><th>Time</th><th>Action</th></tr>" + (rows or "<tr><td colspan=5>None</td></tr>") + "</table></div>"
    return render_template_string(STYLE + NAV + body)

@app.route('/flags/<int:flag_id>/remove', methods=['POST'])
@login_required
def flag_remove(flag_id):
    f = get_flag(flag_id)
    if f:
        chat_id, admin_id = f[1], f[2]
        try:
            demote_admin(chat_id, admin_id)
            bot.send_message(chat_id, "Warning: an admin was removed due to misconduct.")
        except Exception as e:
            print(e)
        resolve_flag(flag_id, 'removed')
    return redirect(url_for('flags_page'))

@app.route('/flags/<int:flag_id>/ignore', methods=['POST'])
@login_required
def flag_ignore(flag_id):
    resolve_flag(flag_id, 'ignored')
    return redirect(url_for('flags_page'))

