"""
Test script to verify alert timer auto-send functionality
"""
import time
import requests

# Test configuration
BASE_URL = "http://127.0.0.1:5000"
API_KEY = ""  # Add your API key here

def test_timer_auto_send():
    """Test that periodic batch alerts auto-send when timer expires"""
    print("=" * 60)
    print("Testing Periodic Batch Alert Auto-Send")
    print("=" * 60)
    
    # 1. Get current config
    print("\n1. Getting current config...")
    resp = requests.get(
        f"{BASE_URL}/v1/config/org/123",
        headers={"X-API-Key": API_KEY}
    )
    config = resp.json()
    print(f"   Current notification mode: {config.get('alerts', {}).get('notification_mode', 'unknown')}")
    
    # 2. Set to periodic mode with short interval (1 minute for testing)
    print("\n2. Setting notification mode to 'batch' with 1 minute interval...")
    config['alerts']['notification_mode'] = 'batch'
    config['alerts']['check_interval_min'] = 1
    config['alerts']['enabled'] = True
    
    resp = requests.post(
        f"{BASE_URL}/v1/config/org/123",
        json=config,
        headers={"X-API-Key": API_KEY, "Content-Type": "application/json"}
    )
    if resp.status_code == 200:
        print("   ✓ Config saved successfully")
    else:
        print(f"   ✗ Failed to save config: {resp.status_code}")
        return
    
    # 3. Check alert history before waiting
    print("\n3. Checking alert history before timer expires...")
    resp = requests.get(
        f"{BASE_URL}/api/alerts/history",
        headers={"X-API-Key": API_KEY}
    )
    history_before = resp.json()
    print(f"   Alert history entries: {len(history_before)}")
    
    # 4. Wait for timer to expire (1 minute + buffer)
    print("\n4. Waiting for timer to expire (65 seconds)...")
    print("   Timer should auto-send batch webhook when it hits zero...")
    for i in range(65, 0, -5):
        print(f"   {i} seconds remaining...")
        time.sleep(5)
    
    # 5. Check alert history after timer
    print("\n5. Checking alert history after timer expires...")
    time.sleep(2)  # Small buffer for processing
    resp = requests.get(
        f"{BASE_URL}/api/alerts/history",
        headers={"X-API-Key": API_KEY}
    )
    history_after = resp.json()
    print(f"   Alert history entries: {len(history_after)}")
    
    # 6. Verify new alerts were sent
    new_alerts = len(history_after) - len(history_before)
    print(f"\n6. Results:")
    if new_alerts > 0:
        print(f"   ✓ SUCCESS: {new_alerts} new alert(s) sent automatically")
        print(f"   ✓ Timer auto-send is working correctly!")
    else:
        print(f"   ✗ FAILED: No new alerts sent")
        print(f"   ✗ Timer may not be triggering auto-send")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    # Get API key from user
    api_key_input = input("Enter your API key (or press Enter to use stored key): ").strip()
    if api_key_input:
        API_KEY = api_key_input
    else:
        # Try to get from localStorage (if running from browser context)
        print("Note: You'll need to provide an API key for this test")
        print("You can find it in your browser's localStorage under 'api_key'")
        API_KEY = input("API Key: ").strip()
    
    if not API_KEY:
        print("Error: API key is required")
        exit(1)
    
    test_timer_auto_send()
