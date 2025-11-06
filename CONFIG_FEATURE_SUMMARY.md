# Crawler Configuration Feature - Implementation Summary

## 🎯 What Was Built

A complete **Crawler Configuration UI** that allows users to customize:
- **Watchlist**: Domains, emails, and keywords to monitor
- **Crawler Settings**: Per-crawler parameters (limits, timeouts, keywords)
- **Alert Settings**: Notification preferences and thresholds

---

## 📁 Files Created/Modified

### **New Files:**
1. **`templates/config.html`** - Configuration page UI
2. **`static/js/config.js`** - Configuration page logic
3. **`CONFIG_FEATURE_SUMMARY.md`** - This documentation

### **Modified Files:**
1. **`backend/app.py`**:
   - Added `/config` and `/config/` routes
   - Updated `/v1/config/org/<org_id>` to support GET and POST
   - Added `/v1/config/org/<org_id>/reset` endpoint
   - Added in-memory config storage (`_ORG_CONFIGS` dict)

2. **`templates/leaks.html`**:
   - Added "Crawler Settings" button in toolbar (top-right)
   - Links to `/config` page

---

## 🎨 UI Features

### **Three-Tab Interface:**

#### **1. Watchlist Tab**
Configure what to monitor:
- **Domains**: `example.com, test.org` (comma-separated)
- **Emails**: `admin@example.com, security@company.com`
- **Keywords**: `password, login, credentials, breach`

#### **2. Crawlers Tab**
Per-crawler settings with icons:

**🗒️ Pastebin**
- Limit: Max pastes per run (1-100)
- Rate Limit: Wait time between requests (ms)
- Timeout: Request timeout (seconds)

**🕵️ Tor**
- SOCKS Port: Proxy port (9050 or 9150)
- Timeout: Request timeout (longer for Tor)
- Keywords: Search filters

**🌐 I2P**
- Proxy Host: I2P router address
- Proxy Port: HTTP proxy port (4444)
- Timeout: Request timeout
- Keywords: Search filters

**💻 GitHub**
- API Token: GitHub personal access token (password field)
- Limit: Max results per search
- Timeout: Request timeout
- Keywords: Code search terms

#### **3. Alerts Tab**
Notification settings:
- **Enable Alerts**: Toggle automated notifications
- **Alert Threshold**: Critical Only | High+ | Medium+ | All
- **Email**: Where to send notifications
- **Webhook URL**: Slack/Discord/custom webhook
- **Check Interval**: How often to check (minutes)

### **Action Buttons:**
- **💾 Save Configuration**: Persist changes
- **🔄 Reset to Defaults**: Restore default settings
- **Status Messages**: Real-time feedback (green=success, red=error)

---

## 🔧 How It Works

### **Data Flow:**

```
┌──────────────────────────────────────────────┐
│  1. User Opens Config Page (/config)        │
│     GET /v1/config/org/123                   │
└──────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────┐
│  2. Backend Returns Current Config           │
│     (from _ORG_CONFIGS or defaults)          │
└──────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────┐
│  3. JavaScript Populates Form Fields         │
│     config.js: populateForm(config)          │
└──────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────┐
│  4. User Edits Settings & Clicks "Save"     │
│     POST /v1/config/org/123 with JSON        │
└──────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────┐
│  5. Backend Stores in _ORG_CONFIGS           │
│     (in production: save to database)        │
└──────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────┐
│  6. Crawlers Load Updated Config             │
│     backend/crawler/*.py calls load_config() │
└──────────────────────────────────────────────┘
```

### **Backend API Endpoints:**

#### **GET `/v1/config/org/<org_id>`**
Returns current configuration (custom or defaults):
```json
{
  "watchlist": {
    "domains": ["example.com"],
    "emails": ["admin@example.com"],
    "keywords": ["password", "login"]
  },
  "sources": {
    "pastebin": { "limit": 5, "rate_limit_ms": 500, "timeout_sec": 15 },
    "tor": { "socks_port": 9050, "timeout_sec": 40, "keywords": [...] },
    "i2p": { "proxy_host": "127.0.0.1", "proxy_port": 4444, ... },
    "github": { "token": "ghp_xxx", "limit": 10, ... }
  },
  "alerts": {
    "enabled": true,
    "threshold": "critical",
    "email": "",
    "webhook": "",
    "check_interval_min": 15
  }
}
```

#### **POST `/v1/config/org/<org_id>`**
Saves user configuration:
- **Auth Required**: Yes (checks `get_current_user_id()`)
- **Body**: JSON config object
- **Response**: `{"status": "saved", "config": {...}}`

#### **POST `/v1/config/org/<org_id>/reset`**
Resets to defaults:
- **Auth Required**: Yes
- **Action**: Deletes custom config from `_ORG_CONFIGS`
- **Response**: `{"status": "reset"}`

---

## 🚀 How to Use

### **As a User:**

1. **Access Config Page**:
   - Click "Crawler Settings" button on Leaks page (top-right)
   - Or navigate directly to `/config`

2. **Edit Settings**:
   - Switch between tabs (Watchlist, Crawlers, Alerts)
   - Update values in form fields
   - Click "Save Configuration"

3. **Reset if Needed**:
   - Click "Reset to Defaults"
   - Confirm dialog
   - Config restored to system defaults

4. **Run Crawlers**:
   - Go to Leaks page
   - Click "Run Pastebin" (or other crawler buttons)
   - Crawler automatically uses your saved settings

### **As a Developer:**

**Current State (In-Memory Storage):**
```python
# backend/app.py
_ORG_CONFIGS = {}  # Stored in memory (resets on server restart)
```

**Production Upgrade (Database Storage):**
```python
# Create a Config model
class OrgConfig(Base):
    __tablename__ = 'org_configs'
    org_id = Column(Integer, primary_key=True)
    config_json = Column(JSON)
    updated_at = Column(DateTime, default=datetime.utcnow)

# Update endpoints to use DB:
@app.route("/v1/config/org/<int:org_id>", methods=["POST"])
def get_config(org_id):
    if request.method == "POST":
        session = SessionLocal()
        config = session.query(OrgConfig).filter_by(org_id=org_id).first()
        if not config:
            config = OrgConfig(org_id=org_id)
        config.config_json = request.json
        session.add(config)
        session.commit()
        session.close()
        return jsonify({"status": "saved"})
```

---

## 🎨 UI Consistency

The config page matches the app's design system:

- **Sidebar**: Icon-only navigation with gear icon (⚙️) active
- **Section Heading**: "Crawler Configuration" title
- **Tabs**: Same tab styling as Leaks page
- **Colors**: Dark theme with `new.css` variables
- **Inputs**: Consistent styling with `base.css`
- **Buttons**: Primary (red) and secondary (gray) buttons
- **Icons**: Font Awesome icons throughout
- **Responsive**: Grid layout adapts to screen size

---

## 🔮 Future Enhancements

### **Phase 1: Persistence** (Recommended Next)
- [ ] Create `OrgConfig` database model
- [ ] Migrate from `_ORG_CONFIGS` dict to SQLite
- [ ] Add config history/versioning

### **Phase 2: Validation**
- [ ] Validate email formats
- [ ] Test webhook URLs before saving
- [ ] Validate port numbers and timeouts
- [ ] Show GitHub token status (valid/invalid)

### **Phase 3: Advanced Features**
- [ ] Schedule automated crawler runs
- [ ] Industry-specific keyword templates
- [ ] Import/export config as JSON
- [ ] Multi-org support with role-based access
- [ ] Audit log of config changes

### **Phase 4: Alerting System** (Critical Gap)
- [ ] Background job using saved alert settings
- [ ] Email notifications via Flask-Mail
- [ ] Webhook POST to Slack/Discord
- [ ] Alert history and acknowledgment

---

## 📊 Impact on Existing Features

### **Crawlers Now Use Saved Config:**
When you click "Run Pastebin" on Leaks page:
1. Frontend sends POST to `/api/crawlers/pastebin/run`
2. Backend calls `pastebin.fetch_and_store()`
3. Crawler calls `get_source_cfg()` → loads from `/v1/config/org/123`
4. Uses **your saved limit, rate_limit, timeout**
5. Extracts entities and matches against **your watchlist**

### **Backward Compatibility:**
- If no custom config exists → uses hardcoded defaults
- Function arguments override config values
- Existing crawlers work without modification

---

## ✅ Testing Checklist

- [ ] Load config page (`/config`)
- [ ] Edit watchlist domains and save
- [ ] Edit Pastebin limit and save
- [ ] Reset to defaults (confirm dialog works)
- [ ] Run Pastebin crawler (check it uses new limit)
- [ ] Verify config persists on page reload
- [ ] Test with multiple org_ids (change localStorage)
- [ ] Verify auth requirement (logout and try to save)

---

## 🐛 Known Limitations

1. **In-Memory Storage**: Config resets on server restart (upgrade to DB)
2. **No Multi-Org UI**: Must manually change `localStorage.setItem('org_id', '456')`
3. **GitHub Token Not Tested**: No validation on save
4. **Webhook Not Functional**: Alerts system not implemented yet
5. **No Config Import/Export**: Can't backup/restore configs

---

## 📝 Code Locations

**Frontend:**
- Template: `templates/config.html`
- JavaScript: `static/js/config.js`
- Button on Leaks: `templates/leaks.html` (line ~31)

**Backend:**
- Routes: `backend/app.py` (search for `/config` and `/v1/config/org`)
- Config loader: `backend/crawler/config.py`
- Crawler usage: `backend/crawler/pastebin.py` (and others)

**Assets:**
- Uses existing CSS: `dashboard/new.css` + `dashboard/base.css`
- Icons: Font Awesome 7.0.1 (CDN)

---

## 🎓 Next Steps for You

1. **Test the Config Page**:
   ```bash
   # Start Flask server
   cd C:\Users\rsjwn\Desktop\WebCrawler\490_Senior_Project
   python -m backend.app
   
   # Open browser: http://127.0.0.1:5000/config
   ```

2. **Make Changes**:
   - Edit watchlist domains
   - Change Pastebin limit to 3
   - Save config

3. **Run a Crawler**:
   - Go to Leaks page
   - Click "Run Pastebin"
   - Verify it only fetches 3 pastes (your new limit)

4. **Decide on Next Feature**:
   - **Option A**: Implement Alerting System (uses saved alert settings)
   - **Option B**: Add database persistence for configs
   - **Option C**: Build Compliance Reports export

---

**Which feature would you like to build next?**
