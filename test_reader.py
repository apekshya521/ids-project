from reading.log_reader import read_logs
from normalization.normalizer import normalize
from detection.detector import detect

logs = read_logs()
print(f"Total logs: {len(logs)}")
print()

for log in logs:
    clean  = normalize(log)
    result = detect(clean)

    print(f"EventID     : {result['event_id']}")
    print(f"Description : {result['description']}")
    print(f"Risk        : {result['risk_level']}")
    print(f"Reason      : {result['reason']}")
    print(f"Channel     : {result['channel']}")
    print(f"Time        : {result['time']}")
    print(f"Computer    : {result['computer']}")
    print(f"Username    : {result['username']}")
    print(f"IP Address  : {result['ip_address']}")
    print("---")
