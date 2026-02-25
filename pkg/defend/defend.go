// Package defend provides model poisoning defense mechanisms.
package defend

import (
	"math"
)

// DefenseStrategy represents a defense strategy.
type DefenseStrategy struct {
	Name        string
	Description string
	Effectiveness float64
	Overhead    float64
	Type        string
}

// DefenseResult contains defense results.
type DefenseResult struct {
	Success       bool
	StrategyUsed  string
	Improvement   float64
	RiskReduction float64
	Cost          float64
}

// Defender applies model poisoning defenses.
type Defender struct {
	strategies []DefenseStrategy
}

// NewDefender creates a new poisoning defender.
func NewDefender() *Defender {
	return &Defender{
		strategies: []DefenseStrategy{
			{
				Name:        "Data Cleaning",
				Description: "Remove suspicious samples",
				Effectiveness: 0.75,
				Overhead:    0.2,
				Type:        "preprocessing",
			},
			{
				Name:        "Robust Aggregation",
				Description: "Use robust aggregation methods",
				Effectiveness: 0.8,
				Overhead:    0.15,
				Type:        "aggregation",
			},
			{
				Name:        "Input Filtering",
				Description: "Filter malicious inputs",
				Effectiveness: 0.7,
				Overhead:    0.1,
				Type:        "filtering",
			},
			{
				Name:        "Adversarial Training",
				Description: "Train on poisoned examples",
				Effectiveness: 0.85,
				Overhead:    0.4,
				Type:        "training",
			},
			{
				Name:        "Outlier Detection",
				Description: "Detect and remove outliers",
				Effectiveness: 0.65,
				Overhead:    0.12,
				Type:        "detection",
			},
			{
				Name:        "Ensemble Defense",
				Description: "Use multiple models",
				Effectiveness: 0.9,
				Overhead:    0.5,
				Type:        "ensemble",
			},
		},
	}
}

// Defend applies defense strategy.
func (d *Defender) Defend(poisoningRisk float64, strategy string) *DefenseResult {
	for _, strat := range d.strategies {
		if strat.Name == strategy {
			// Calculate improvement
			improvement := strat.Effectiveness * poisoningRisk
			riskReduction := poisoningRisk - improvement

			return &DefenseResult{
				Success:      true,
				StrategyUsed: strat.Name,
				Improvement:  improvement,
				RiskReduction: riskReduction,
				Cost:         strat.Overhead,
			}
		}
	}

	return &DefenseResult{
		Success: false,
	}
}

// ApplyDefense applies defense to dataset.
func (d *Defender) ApplyDefense(samples []Sample, strategy string) []Sample {
	for _, strat := range d.strategies {
		if strat.Name == strategy {
			return d.applyStrategy(samples, strat)
		}
	}

	return samples
}

// applyStrategy applies a specific defense strategy.
func (d *Defender) applyStrategy(samples []Sample, strategy DefenseStrategy) []Sample {
	switch strategy.Type {
	case "preprocessing":
		return d.cleanData(samples)
	case "filtering":
		return d.filterInputs(samples)
	case "detection":
		return d.detectOutliers(samples)
	default:
		return samples
	}
}

// cleanData cleans training data.
func (d *Defender) cleanData(samples []Sample) []Sample {
	cleaned := make([]Sample, 0)

	for _, sample := range samples {
		// Remove suspicious samples
		if !d.isSuspicious(sample) {
			cleaned = append(cleaned, sample)
		}
	}

	return cleaned
}

// filterInputs filters malicious inputs.
func (d *Defender) filterInputs(samples []Sample) []Sample {
	filtered := make([]Sample, 0)

	for _, sample := range samples {
		if d.isValidInput(sample) {
			filtered = append(filtered, sample)
		}
	}

	return filtered
}

// detectOutliers detects and marks outliers.
func (d *Defender) detectOutliers(samples []Sample) []Sample {
	// Mark suspicious samples
	for i := range samples {
		if d.isOutlier(samples[i]) {
			samples[i].Metadata["suspicious"] = true
		}
	}

	return samples
}

// isSuspicious checks if sample is suspicious.
func (d *Defender) isSuspicious(sample Sample) bool {
	// Check for unusual patterns
	mean := d.calculateMean(sample.Features)
	stdDev := d.calculateStdDev(sample.Features, mean)

	for _, f := range sample.Features {
		if stdDev > 0 && math.Abs(f-mean)/stdDev > 3.0 {
			return true
		}
	}

	return false
}

// isValidInput checks if input is valid.
func (d *Defender) isValidInput(sample Sample) bool {
	// Basic validation
	if len(sample.Features) == 0 {
		return false
	}

	// Check feature range
	for _, f := range sample.Features {
		if f < -100 || f > 100 {
			return false
		}
	}

	return true
}

// isOutlier checks if sample is outlier.
func (d *Defender) isOutlier(sample Sample) bool {
	mean := d.calculateMean(sample.Features)
	stdDev := d.calculateStdDev(sample.Features, mean)

	if stdDev == 0 {
		return false
	}

	for _, f := range sample.Features {
		if math.Abs(f-mean)/stdDev > 2.5 {
			return true
		}
	}

	return false
}

// calculateMean calculates mean of features.
func (d *Defender) calculateMean(features []float64) float64 {
	if len(features) == 0 {
		return 0
	}

	sum := 0.0
	for _, f := range features {
		sum += f
	}

	return sum / float64(len(features))
}

// calculateStdDev calculates standard deviation.
func (d *Defender) calculateStdDev(features []float64, mean float64) float64 {
	if len(features) == 0 {
		return 0
	}

	sum := 0.0
	for _, f := range features {
		sum += (f - mean) * (f - mean)
	}

	return math.Sqrt(sum / float64(len(features)))
}

// RecommendDefense recommends best defense strategy.
func RecommendDefense(poisoningRisk float64) string {
	if poisoningRisk > 0.7 {
		return "Adversarial Training"
	} else if poisoningRisk > 0.5 {
		return "Ensemble Defense"
	} else if poisoningRisk > 0.3 {
		return "Robust Aggregation"
	} else if poisoningRisk > 0.1 {
		return "Data Cleaning"
	}

	return "Outlier Detection"
}

// CalculateDefenseScore calculates defense effectiveness score.
func CalculateDefenseScore(results []*DefenseResult) float64 {
	if len(results) == 0 {
		return 0.0
	}

	score := 0.0
	for _, result := range results {
		if result.Success {
			score += result.Improvement
		}
	}

	return score / float64(len(results))
}

// GenerateReport generates defense report.
func GenerateReport(result *DefenseResult) string {
	var report string

	report += "=== Model Poisoning Defense Report ===\n\n"
	report += "Success: " + boolToString(result.Success) + "\n"
	report += "Strategy Used: " + result.StrategyUsed + "\n"
	report += "Improvement: " + string(rune(int(result.Improvement*100)+48)) + "%\n"
	report += "Risk Reduction: " + string(rune(int(result.RiskReduction*100)+48)) + "%\n"
	report += "Cost: " + string(rune(int(result.Cost*100)+48)) + "%\n"

	return report
}

// boolToString converts bool to string.
func boolToString(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}