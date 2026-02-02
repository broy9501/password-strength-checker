# 🔐 Password Strength Checker

A cybersecurity-focused Python tool that evaluates password strength by analysing entropy, character variety, real-world attack patterns, and estimated crack times.

This project simulates how attackers assess passwords and provides actionable security feedback to help users create stronger credentials.

---

## 🚀 Features

- Secure masked password input
- Character variety analysis
- Entropy calculation (randomness estimation)
- Real-world attack pattern detection (via zxcvbn)
- Offline and online crack time estimation
- Security warnings and improvement suggestions
- JSON report generation
- Privacy-focused (no password storage)

---

## 🧠 How It Works

1. Securely accepts password input (masked)
2. Analyses length and character diversity
3. Calculates entropy based on character pool
4. Detects common attack patterns
5. Estimates cracking time
6. Generates a security report
7. Saves detailed results in JSON format

---

## ⚙️ Technologies Used

- Python
- maskpass (secure input)
- zxcvbn (password analysis)
- regex (pattern detection)
- JSON (reporting)
