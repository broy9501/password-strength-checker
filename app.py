# import getpass
# password = getpass.getpass("Enter your password: ")
# print("Password entered successfully.")

import maskpass
import re
from zxcvbn import zxcvbn
import math
import json

# Mask and get the password input
password = maskpass.askpass(prompt="Enter your password: ", mask="*")

# Calculate character varierty score
def characterVariety(password):
    varietyScore = 0
    if re.search(r'[a-z]', password): varietyScore += 1

    if re.search(r'[A-Z]', password): varietyScore += 1

    # if re.search(r'[0-9]', password):
    if re.search(r'\d', password): varietyScore += 1

    if re.search(r'[^A-Za-z0-9]', password): varietyScore +=1

    if re.search(r'(.)\1\1', password):
        varietyScore -= 1
    else:
        varietyScore += 1
    return varietyScore
    
variety = characterVariety(password)
length = len(password) # Length of paasword

def entropyScore(length, password):
    # Calculating pool size for number of possible chatarcters
    if not password:
        return 0
    
    pool = 0

    if re.search(r'[a-z]', password): pool += 26

    if re.search(r'[A-Z]', password): pool += 26

    if re.search(r'\d', password): pool += 10

    if re.search(r'[^A-Za-z0-9]', password): pool += 32

    # Calculating entropy score
    entropyScore = length * math.log2(pool)

    return entropyScore

entropy = entropyScore(length, password)
print(f"{entropy} bits of entropy")
print("\n")

result = zxcvbn(password) # Getting all details of the password with zxcvbn library

# Find attack patterns of password
patterns = [match['pattern'] for match in result['sequence']]
print("Attack patterns found: ")
for pattern in patterns:
    print(f" - {pattern}")
print("\n")

# Get crack time of password
crackTimeOffline = result['crack_times_display']['offline_fast_hashing_1e10_per_second']
crackTimeOnline = result['crack_times_display']['online_no_throttling_10_per_second']
print(crackTimeOffline)
print(crackTimeOnline)

print("\n")

# Warning of the password if weak
warning = result['feedback']['warning']
if warning:
    print(f"Warning: {warning}")

print("\n")

# Provide suggestions to improve password
suggestions = []
suggestions.extend(result['feedback']['suggestions'])
if variety < 3:
    suggestions.append("Use a mix of uppercase, lowercase, numbers, and symbols.")
if length < 8:
    suggestions.append("Make your password at least 8 characters long.")
if entropy < 50:
    suggestions.append("Increase the complexity of your password to improve entropy.")
if suggestions:
    print("Suggestions to improve your password: ")
    for suggestion in suggestions:
        print(f" - {suggestion} ")

print("\n")

with open('zxcvbn_result.json', 'w', encoding='utf-8') as f:
    json.dump(result, f, indent=4, default=str)

data = {
    "length": length,
    "variety": variety,
    "entropy": entropy,
    "crack_time_offline": crackTimeOffline,
    "crack_time_online": crackTimeOnline,
    "patterns": patterns,
    "warning": warning,
    "Suggestions": suggestions
}

with open('password_strength_summary.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=4, default=str)

# print(result)
