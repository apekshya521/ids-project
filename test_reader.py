from reading.log_reader import read_all_logs
from normalization.normalizer import normalize
from detection.detector import detect
from scoring.scorer import calculate_score

# Read all 3 channels
logs = read_all_logs()
print(f"Total logs: {len(logs)}")
print()

# Counters
high   = 0
medium = 0
low    = 0
normal = 0

for log in logs:
    clean   = normalize(log)
    result  = detect(clean)
    final   = calculate_score(result)

    print(f"EventID     : {final['event_id']}")
    print(f"Description : {final['description']}")
    print(f"Risk        : {final['risk_level']}")
    print(f"Source      : {log['source']}")

    print(f"Reason      : {final['reason']}")
    print(f"Channel     : {final['channel']}")
    print(f"Time        : {final['time']}")
    print(f"Computer    : {final['computer']}")
    print(f"Username    : {final['username']}")
    print(f"IP Address  : {final['ip_address']}")
    print("---")

    # Count risk levels
    if final['risk_level'] == "High":   high   += 1
    if final['risk_level'] == "Medium": medium += 1
    if final['risk_level'] == "Low":    low    += 1
    if final['risk_level'] == "Normal": normal += 1

# Summary
print()
print("===== SUMMARY =====")
print(f"Total Logs : {len(logs)}")
print(f"🔴 High    : {high}")
print(f"🟡 Medium  : {medium}")
print(f"🟢 Low     : {low}")
print(f"⚪ Normal  : {normal}")