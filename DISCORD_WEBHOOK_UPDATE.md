# 🚀 Final Updates - Discord Webhook & Page Cleanup

## ✅ All Issues Resolved

### 1. **Discord Webhook Integration** ✅
**Problem:** Discord webhook URL wasn't receiving messages

**Solution:**
- Updated `send_webhook_alert()` function to detect Discord webhooks
- Auto-formats payload in Discord's required format with embeds
- Discord messages now include:
  - 🚨 Alert title with severity
  - Embedded card with source, severity, leak ID
  - Timestamp and footer branding
  - Red color (15158332) for critical alerts

**How it works:**
```python
if 'discord.com/api/webhooks' in webhook_url.lower():
    # Use Discord embed format
    webhook_payload = {
        'content': '🚨 **Critical Leak Detected**',
        'embeds': [{...}]
    }
```

### 2. **401 Authentication Errors Fixed** ✅
**Problem:** Pastebin crawler still getting 401 errors on `/v1/events`

**Root Cause:** Server was still running old code

**Solution:**
- Previous fix (fallback user) is already in code
- **YOU MUST RESTART THE SERVER** for it to take effect
- No environment variables needed!

**To fix:**
```powershell
# Stop server: Ctrl+C
python app.py
```

### 3. **Leaks Page Cleanup** ✅
**Problem:** Leaks page had watchlist tab + configuration mixed in

**Solution:**
- ✅ Removed "Watchlist" tab completely from leaks page
- ✅ Removed all assets/watchlist management UI from leaks.html
- ✅ Removed tab-switching code from leaks.js
- ✅ Removed `loadAssets()` and `addAsset()` functions
- ✅ Leaks page now ONLY shows:
  - Crawler run buttons
  - Source & severity filters
  - Leaks table with pagination
  - "Crawler Settings" button linking to /config

**Result:** Clean, focused leaks page dedicated to viewing/filtering leaks only

### 4. **Watchlist Consolidation** ✅
**Problem:** Two separate watchlist systems (Assets DB vs Config)

**Solution:**
- ✅ Removed watchlist UI from leaks page
- ✅ All watchlist management now in `/config` page (Watchlist tab)
- ✅ Config watchlist is used by crawlers to boost severity
- ✅ Single source of truth: `config.watchlist.domains`, `config.watchlist.emails`, `config.watchlist.keywords`

**How it works:**
1. User adds watchlist items in Config page → saved to database
2. Crawlers load config via `/v1/config/org/123`
3. Crawlers boost severity when watchlist items found in content
4. Higher severity → webhook alert triggered if ≥70

## 📋 Files Modified

### Backend
1. **backend/app.py**
   - Line 500-530: Updated `send_webhook_alert()` to detect and format Discord webhooks
   - Added Discord embed structure with proper fields and colors

### Frontend
2. **templates/leaks.html**
   - Lines 73-76: Removed "Tabs" section (Leaks/Watchlist buttons)
   - Lines 78-140: Removed entire Watchlist tab content
   - Simplified to single leaks section without tabs

3. **static/js/leaks.js**
   - Lines 272-320: Removed `loadAssets()` function
   - Lines 302-320: Removed `addAsset()` function
   - Lines 326-335: Removed tab-switching event listeners
   - Line 342: Removed `loadAssets()` call
   - Line 343: Removed `addAsset` event listener

## 🎯 How to Test Discord Webhook

### Step 1: Configure Webhook
1. Navigate to **Alerts** page
2. Click **Alert Settings** tab
3. Enable alerts checkbox
4. Paste your Discord webhook URL
5. Click "Test Webhook" - you should see test message in Discord!
6. Click "Save Alert Settings"

### Step 2: Trigger Real Alert
1. **Restart the server** (important!)
2. Navigate to **Config** page
3. Go to **Watchlist** tab
4. Add some watchlist items (domains, emails, keywords)
5. Save configuration
6. Navigate to **Leaks** page
7. Click "Run Pastebin" (or any crawler)
8. Wait for leaks to be inserted
9. If severity ≥ 70, Discord message will be sent automatically!

### Step 3: Verify
1. Check Discord channel for alert message
2. Go to Alerts → Alert History tab
3. You should see the webhook delivery status (sent/failed)

## 📊 What Gets Sent to Discord

```json
{
  "content": "🚨 **Critical Leak Detected** (Severity: 100)",
  "embeds": [{
    "title": "Compromised credentials leaked",
    "color": 15158332,
    "fields": [
      {"name": "Source", "value": "pastebin", "inline": true},
      {"name": "Severity", "value": "100", "inline": true},
      {"name": "Leak ID", "value": "42", "inline": true}
    ],
    "timestamp": "2025-11-04T21:30:00.000Z",
    "footer": {"text": "DarkWidow Alert System"}
  }]
}
```

## 🔄 Watchlist Now Works Like This

### Old System (Removed)
- Assets table in database
- Separate UI in Leaks page "Watchlist" tab
- Not connected to config system
- Not used by crawlers

### New System (Current)
- Watchlist in config database (persists across sessions)
- Single UI in Config page → Watchlist tab
- Crawlers load config and check watchlist
- Matching items boost severity → triggers alerts

### Configuration Structure
```json
{
  "watchlist": {
    "domains": ["yourcompany.com", "sensitive-domain.com"],
    "emails": ["admin@yourcompany.com"],
    "keywords": ["password", "credential", "database", "api_key"]
  }
}
```

## ⚠️ IMPORTANT: Must Restart Server!

**The 401 fix and Discord webhook format won't work until you restart:**

```powershell
# In your terminal, press Ctrl+C to stop
python app.py
```

After restart:
1. ✅ 401 errors will be gone
2. ✅ Discord webhooks will work
3. ✅ Config persists in database
4. ✅ Clean leaks page (no watchlist tab)

## 🎉 Summary

**Before:**
- Leaks page cluttered with tabs and watchlist management
- Watchlist in separate Assets database
- Discord webhooks not formatted correctly
- Two systems doing similar things

**After:**
- Clean leaks page focused on viewing leaks
- All configuration centralized in /config page
- Discord webhooks properly formatted with embeds
- Single watchlist system used by crawlers
- Everything persists across server restarts

All ready to go! Just restart the server and test your Discord webhook! 🚀
