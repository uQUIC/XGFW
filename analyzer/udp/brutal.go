// File: analyzer/detector.go
package utils

import (
    "math/rand"
    "time"
)

// Detector struct to monitor packet loss and transmission rate
type Detector struct {
    packetLossRate float64
    transmissionRate float64
}

// NewDetector initializes a new Detector
func NewDetector() *Detector {
    return &Detector{
        packetLossRate:   0.0,
        transmissionRate: 0.0,
    }
}

// UpdateMetrics updates the packet loss rate and transmission rate metrics
func (d *Detector) UpdateMetrics(packetLossRate, transmissionRate float64) {
    d.packetLossRate = packetLossRate
    d.transmissionRate = transmissionRate
}

// Analyze checks if the rate and packet loss have a fixed inverse relationship and returns a bool
func (d *Detector) Analyze() bool {
    // Example condition to check for a fixed inverse relation
    if d.transmissionRate != 0 && (1.0 - d.packetLossRate) > 0 {
        expectedRate := 1.0 / (1.0 - d.packetLossRate)
        return d.transmissionRate == expectedRate
    }
    return false
}

// AdjustTransmissionRate randomly adjusts the transmission rate to avoid detectable patterns
func (d *Detector) AdjustTransmissionRate() float64 {
    rand.Seed(time.Now().UnixNano())
    fluctuation := rand.Float64()*0.1 - 0.05 // Fluctuation in range -0.05 to +0.05
    d.transmissionRate *= (1 + fluctuation)
    return d.transmissionRate
}
