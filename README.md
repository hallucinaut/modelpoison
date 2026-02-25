# modelpoison - AI Model Poisoning Detector

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Detect and defend against data poisoning attacks on machine learning models.**

Protect your ML training pipelines from malicious data injection and model manipulation.

## 🚀 Features

- **Multi-Vector Detection**: Detect backdoor, label flip, gradient, and feature poisoning
- **Training Data Analysis**: Analyze datasets for suspicious samples
- **Defense Mechanisms**: Apply multiple defense strategies
- **Risk Scoring**: Calculate poisoning risk scores
- **Real-time Protection**: Fast detection for production use

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/modelpoison.git
cd modelpoison
go build -o modelpoison ./cmd/modelpoison
sudo mv modelpoison /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/modelpoison/cmd/modelpoison@latest
```

## 🎯 Usage

### Detect Poisoning

```bash
# Detect poisoning in training data
modelpoison detect training_data.csv

# Analyze security
modelpoison analyze
```

### Apply Defenses

```bash
# Defend model against poisoning
modelpoison defend training_data.csv

# Get recommendations
modelpoison recommend
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/modelpoison/pkg/detect"
    "github.com/hallucinaut/modelpoison/pkg/defend"
)

func main() {
    // Create detector
    detector := detect.NewDetector()
    
    // Detect poisoning
    result := detector.Detect(samples)
    
    fmt.Printf("Poisoned samples: %d\n", result.PoisonedCount)
    fmt.Printf("Risk Score: %.0f%%\n", result.RiskScore*100)
    
    // Apply defense
    defender := defend.NewDefender()
    defense := defender.Defend(result.RiskScore, "Data Cleaning")
    
    fmt.Printf("Defense Success: %v\n", defense.Success)
    fmt.Printf("Risk Reduction: %.0f%%\n", defense.RiskReduction*100)
}
```

## 🔍 Attack Types Detected

### Backdoor Attacks

Inject malicious triggers:
- Visual patterns in images
- Specific words in text
- Trigger sequences in time series

### Label Flipping

Corrupt training labels:
- Random label noise
- Targeted label changes
- Consistent mislabeling

### Gradient Poisoning

Manipulate training gradients:
- Byzantine attacks
- Coordinate poisoning
- Gradient compression attacks

### Feature Poisoning

Corrupt input features:
- Feature manipulation
- Statistical outliers
- Distribution shifts

### Data Poisoning

Inject malicious data:
- Malicious samples
- Distribution poisoning
- Concept drift attacks

## 🛡️ Defense Strategies

| Strategy | Effectiveness | Overhead | Use Case |
|----------|--------------|----------|----------|
| Adversarial Training | 85% | 40% | High-security training |
| Ensemble Defense | 90% | 50% | Critical applications |
| Robust Aggregation | 80% | 15% | Distributed training |
| Data Cleaning | 75% | 20% | General use |
| Input Filtering | 70% | 10% | Real-time protection |
| Outlier Detection | 65% | 12% | Quick defense |

## 📊 Risk Levels

| Score | Level | Action |
|-------|-------|--------|
| 0-10% | MINIMAL | Monitor |
| 10-30% | LOW | Review data |
| 30-50% | MEDIUM | Clean data |
| 50-70% | HIGH | Investigate |
| 70-100% | CRITICAL | Block training |

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/detect -run TestDetectPoisoning
```

## 📋 Example Output

```
Detecting poisoning in: training_data.csv

=== Model Poisoning Detection Report ===

Total Samples: 1000
Poisoned Samples: 15
Risk Score: 15%
Method: ensemble_detection

Detected Poisoned Samples:
[1] backdoor
    ID: sample_001
    Type: backdoor
    Score: 78%
    Description: Potential backdoor trigger detected
    Evidence: Unusual feature pattern

⚠️  POISONING DETECTED
Recommendation: Clean training data before training
```

## 🔒 Security Use Cases

- **ML Pipeline Security**: Protect training data from poisoning
- **Model Integrity**: Ensure trained models are clean
- **Data Quality Assurance**: Validate training datasets
- **AI Supply Chain Security**: Secure ML data pipelines
- **Compliance**: Meet AI security requirements

## 🛡️ Best Practices

1. **Validate training data** before training
2. **Monitor for poisoning** during training
3. **Use multiple defenses** for critical systems
4. **Test models** for backdoor behavior
5. **Regular security audits** of ML pipelines
6. **Implement data versioning** for reproducibility

## 🏗️ Architecture

```
modelpoison/
├── cmd/
│   └── modelpoison/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── detect/
│   │   ├── detect.go       # Detection logic
│   │   └── detect_test.go  # Unit tests
│   └── defend/
│       ├── defend.go       # Defense mechanisms
│       └── defend_test.go  # Unit tests
└── README.md
```

## 📄 License

MIT License

## 🙏 Acknowledgments

- Machine learning security research community
- Adversarial machine learning researchers
- AI safety practitioners

## 🔗 Resources

- [Adversarial Machine Learning](https://adversarial-ml-guide.github.io/)
- [ML Security Best Practices](https://mlsec.org/)
- [AI Red Teaming](https://www.microsoft.com/en-us/security/blog/2023/06/21/red-teaming-large-language-models/)

---

**Built with GPU by [hallucinaut](https://github.com/hallucinaut)**