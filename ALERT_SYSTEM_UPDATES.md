# Alert System Updates - November 5, 2025

## Summary of Changes

This document outlines the comprehensive updates made to the alert system to improve functionality, tracking, and automation.

## 1. Reset Alerted Status on Severity Changes ✅

**Files Modified:**
- `backend/database.py`

**Changes:**
- Updated `recompute_severity_for_user_leaks()` to reset `leak.alerted = 0` when severity changes
- Updated `recompute_severity_for_leak()` to reset `leak.alerted = 0` when severity changes
- Added logging to track severity changes

**Behavior:**
- When a leak's severity score is updated (e.g., due to watchlist changes), the `alerted` flag is reset to 0
- This allows the leak to be re-alerted if it now meets or exceeds the configured threshold
- Both immediate and periodic batch modes will pick up these updated leaks

## 2. Trigger Immediate Alerts on Severity Updates ✅

**Files Modified:**
- `backend/app.py` (config save endpoint)

**Changes:**
- Added automatic immediate alert triggering after severity recomputation
- Uses async threading to avoid blocking config save operation
- Only triggers if:
  - Leaks were actually updated (`updated_leaks > 0`)
  - Notification mode is `immediate`
  - Alerts are enabled
  - Webhook URL is configured

**Behavior:**
- When user saves config and watchlist changes cause severity updates
- System automatically batches and sends all non-alerted leaks above threshold
- Runs in background thread to maintain responsive UI

## 3. Auto-Send Batch Alerts When Timer Expires ✅

**Files Modified:**
- `static/js/alert_timer.js`

**Changes:**
- Added `sendBatchWebhook()` function to automatically trigger batch alerts
- Modified `startTimer()` to call `sendBatchWebhook()` when timer reaches zero
- Displays success/failure notifications on alerts page
- Only sends if notification mode is `batch`

**Behavior:**
- Timer counts down from configured interval (e.g., 15 minutes)
- When timer hits 00:00, automatically sends POST to `/api/alerts/send_batch`
- Timer resets for next interval after sending
- Shows status message if user is on alerts page

## 4. Update Alert History for All Webhook Sends ✅

**Files Modified:**
- `backend/app.py` (both batch endpoints)

**Changes:**
- `api_send_batch_webhook()`: Added AlertHistory entry for each leak in batch
- `send_webhook_alert()`: Updated to add AlertHistory entry for each leak (not just first)
- History includes:
  - `leak_id`: ID of the alerted leak
  - `user_id`: User who owns the leak
  - `alert_type`: Always 'webhook'
  - `destination`: Webhook URL
  - `status`: 'sent' or 'failed'
  - `error_message`: HTTP status or exception message if failed
  - `sent_at`: Timestamp of alert

**Behavior:**
- Every webhook send (test or automatic) creates history entries
- One history record per leak in the batch
- Failed webhooks also logged with error details
- History visible in `/api/alerts/history` endpoint

## 5. Severity Score Mapping ✅

**Files Modified:**
- `backend/severity.py`

**Changes:**
- Added `severity_label_to_score()` function
- Mapping:
  - `critical` = 100
  - `high` = 75
  - `medium` = 50
  - `low` = 25
  - `zero severity` / `unknown` = 0

**Updated Threshold Logic:**
- Threshold set to "critical" → only alerts leaks with score >= 100
- Threshold set to "high" → alerts leaks with score >= 75
- Threshold set to "medium" → alerts leaks with score >= 50
- Threshold set to "low" → alerts leaks with score >= 25
- Zero severity leaks (score = 0) are NEVER alerted

## Testing Checklist

### Test Severity Change Detection
1. ✅ Add new watchlist item (email, domain, etc.)
2. ✅ Save config
3. ✅ Verify leaks with matching entities have `alerted` reset to 0
4. ✅ Check immediate alert is triggered if mode is immediate

### Test Periodic Batch Timer
1. ✅ Set notification mode to "Periodic"
2. ✅ Set interval to 1 minute (for quick testing)
3. ✅ Wait for timer to reach zero
4. ✅ Verify batch webhook is sent automatically
5. ✅ Check timer resets for next interval
6. ✅ Verify alert history is updated

### Test Immediate Batch Alerts
1. ✅ Set notification mode to "Immediate"
2. ✅ Create new leak or update watchlist to trigger severity change
3. ✅ Verify batch webhook is sent immediately
4. ✅ Check all non-alerted leaks above threshold are included
5. ✅ Verify alert history is updated

### Test Alert History
1. ✅ Send test batch webhook
2. ✅ Check `/api/alerts/history` endpoint
3. ✅ Verify one entry per leak in batch
4. ✅ Verify entries show correct status ('sent' or 'failed')
5. ✅ Test failed webhook and check error_message is logged

### Test Manual Batch Test
1. ✅ Click "Test Batch Webhook" button
2. ✅ Verify batch is sent
3. ✅ Check alert history includes these test sends
4. ✅ Verify leaks are marked as alerted

## Migration Notes

### Database Schema
- ✅ `alerted` column added to `leaks` table
- ✅ Default value: 0 (not alerted)
- ✅ Migration script: `scripts/add_alerted_column.py`

### Breaking Changes
- None - all changes are backward compatible
- Existing leaks default to `alerted=0` so they will be picked up by next alert cycle

## Architecture Overview

```
┌─────────────────────┐
│  Severity Change    │
│  (Watchlist Update) │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Reset alerted=0     │
│ for changed leaks   │
└──────────┬──────────┘
           │
           ├─────────────────┐
           │                 │
           ▼                 ▼
┌──────────────────┐  ┌──────────────────┐
│ Immediate Mode   │  │ Periodic Mode    │
│ (Batch on detect)│  │ (Batch on timer) │
└────────┬─────────┘  └────────┬─────────┘
         │                     │
         │ Trigger now         │ Wait for timer
         │                     │
         └─────────┬───────────┘
                   │
                   ▼
          ┌─────────────────┐
          │ Query non-alerted│
          │ leaks >= threshold│
          └────────┬─────────┘
                   │
                   ▼
          ┌─────────────────┐
          │ Send batch webhook│
          └────────┬─────────┘
                   │
                   ├───────────────┐
                   │               │
                   ▼               ▼
          ┌──────────────┐  ┌──────────────┐
          │ Mark alerted=1│  │ Save to      │
          │ for each leak │  │ AlertHistory │
          └──────────────┘  └──────────────┘
```

## Future Enhancements

1. **Email Alerts**: Implement email notification support alongside webhooks
2. **Alert Throttling**: Add rate limiting to prevent alert spam
3. **Custom Batch Grouping**: Allow grouping by source, severity, or time window
4. **Alert Templates**: Customizable webhook payload templates
5. **Retry Logic**: Automatic retry for failed webhook deliveries
6. **Alert Analytics**: Dashboard showing alert delivery metrics

## Changelog

### v2.0.0 - November 5, 2025
- Added automatic severity change detection and re-alerting
- Implemented periodic batch timer auto-send
- Added comprehensive alert history tracking
- Created severity score mapping system
- Fixed immediate mode to batch all non-alerted leaks
- Added async alert triggering for config changes
