//! Transaction Fee Mechanism (ZIP-224 Compliant)

#![allow(missing_docs)]
//!
//! This module implements transaction fees for Tachyon following ZIP-224 principles:
//! - Conventional fee computation based on logical action count
//! - Transparent fee pool for miner rewards
//! - Fee payment via transparent outputs or shielded-to-transparent
//! - Marginal fee rate: 1000 zatoshis per logical action
//!
//! # Fee Structure
//!
//! ```text
//! base_fee = 1000 zatoshis (minimum)
//! fee_per_action = 1000 zatoshis
//! total_fee = base_fee + (num_actions * fee_per_action)
//! ```
//!
//! # Logical Actions
//!
//! - Traditional Action: 2 logical actions (1 spend + 1 output)
//! - Tachyaction: 2 logical actions (1 spend + 1 output, proof-carrying)
//! - Transparent input: 0 logical actions (no privacy cost)
//! - Transparent output: 0 logical actions (fee payment, no privacy cost)
//!
//! # Fee Payment Methods
//!
//! 1. **Transparent to Shielded**: Include fee in transaction balance
//! 2. **Shielded to Shielded**: Create transparent output for fee
//! 3. **Shielded to Transparent**: Deduct fee from transparent output

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::bundle::TachyBundle;

// ----------------------------- Constants -----------------------------

/// Minimum transaction fee (base fee)
pub const BASE_FEE_ZATOSHIS: u64 = 1000;

/// Fee per logical action
pub const FEE_PER_ACTION_ZATOSHIS: u64 = 1000;

/// Maximum reasonable fee (safety limit)
pub const MAX_FEE_ZATOSHIS: u64 = 100_000_000; // 1 ZEC

/// 1 ZEC in zatoshis
pub const COIN: u64 = 100_000_000;

// ----------------------------- Fee Calculation -----------------------------

/// Calculate the required fee for a transaction
///
/// # Arguments
/// - `num_traditional_actions`: Number of Traditional Actions
/// - `num_tachyactions`: Number of Tachyactions
/// - `num_transparent_inputs`: Number of transparent inputs
/// - `num_transparent_outputs`: Number of transparent outputs (excluding fee output)
///
/// # Returns
/// Total fee in zatoshis
pub fn calculate_fee(
    num_traditional_actions: usize,
    num_tachyactions: usize,
    num_transparent_inputs: usize,
    num_transparent_outputs: usize,
) -> u64 {
    // Each Traditional Action = 2 logical actions (spend + output)
    let traditional_logical = num_traditional_actions * 2;
    
    // Each Tachyaction = 2 logical actions (spend + output)
    let tachyaction_logical = num_tachyactions * 2;
    
    // Transparent inputs/outputs don't count (no privacy cost)
    let _ = (num_transparent_inputs, num_transparent_outputs);
    
    let total_logical_actions = traditional_logical + tachyaction_logical;
    
    BASE_FEE_ZATOSHIS + (total_logical_actions as u64 * FEE_PER_ACTION_ZATOSHIS)
}

/// Calculate fee for a bundle
pub fn calculate_bundle_fee(bundle: &TachyBundle) -> u64 {
    calculate_fee(
        bundle.actions.len(),
        bundle.tachyactions.len(),
        0, // Bundle doesn't track transparent inputs
        0, // Bundle doesn't track transparent outputs
    )
}

/// Fee policy for transaction construction
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FeePolicy {
    /// Fee rate in zatoshis per logical action
    pub fee_per_action: u64,
    
    /// Base fee in zatoshis
    pub base_fee: u64,
    
    /// Maximum fee willing to pay (safety limit)
    pub max_fee: u64,
}

impl FeePolicy {
    /// Standard fee policy (ZIP-224 compliant)
    pub fn standard() -> Self {
        Self {
            fee_per_action: FEE_PER_ACTION_ZATOSHIS,
            base_fee: BASE_FEE_ZATOSHIS,
            max_fee: MAX_FEE_ZATOSHIS,
        }
    }

    /// High priority fee policy (2x standard)
    pub fn high_priority() -> Self {
        Self {
            fee_per_action: FEE_PER_ACTION_ZATOSHIS * 2,
            base_fee: BASE_FEE_ZATOSHIS * 2,
            max_fee: MAX_FEE_ZATOSHIS,
        }
    }

    /// Low priority fee policy (0.5x standard, may be slow)
    pub fn low_priority() -> Self {
        Self {
            fee_per_action: FEE_PER_ACTION_ZATOSHIS / 2,
            base_fee: BASE_FEE_ZATOSHIS / 2,
            max_fee: MAX_FEE_ZATOSHIS,
        }
    }

    /// Custom fee policy
    pub fn custom(fee_per_action: u64, base_fee: u64, max_fee: u64) -> Self {
        Self {
            fee_per_action,
            base_fee,
            max_fee,
        }
    }

    /// Calculate fee using this policy
    pub fn calculate_fee(
        &self,
        num_traditional_actions: usize,
        num_tachyactions: usize,
    ) -> Result<u64, FeeError> {
        let traditional_logical = num_traditional_actions * 2;
        let tachyaction_logical = num_tachyactions * 2;
        let total_logical = traditional_logical + tachyaction_logical;

        let fee = self.base_fee + (total_logical as u64 * self.fee_per_action);

        if fee > self.max_fee {
            return Err(FeeError::FeeTooHigh(fee, self.max_fee));
        }

        Ok(fee)
    }

    /// Check if a fee is sufficient for a transaction
    pub fn is_sufficient(&self, fee: u64, num_actions: usize) -> bool {
        let required = self.base_fee + (num_actions as u64 * 2 * self.fee_per_action);
        fee >= required
    }
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self::standard()
    }
}

/// Fee payment method
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FeePayment {
    /// Pay fee from transparent balance
    FromTransparent {
        /// Amount to pay
        amount: u64,
    },
    
    /// Pay fee by creating transparent output from shielded
    FromShielded {
        /// Amount to pay
        amount: u64,
        /// Transparent address to send fee to (miner)
        to_address: Vec<u8>,
    },
    
    /// Deduct fee from existing transparent output
    DeductFromOutput {
        /// Index of output to deduct from
        output_index: usize,
        /// Amount to deduct
        amount: u64,
    },
}

impl FeePayment {
    /// Get the fee amount
    pub fn amount(&self) -> u64 {
        match self {
            FeePayment::FromTransparent { amount } => *amount,
            FeePayment::FromShielded { amount, .. } => *amount,
            FeePayment::DeductFromOutput { amount, .. } => *amount,
        }
    }

    /// Validate fee payment
    pub fn validate(&self) -> Result<(), FeeError> {
        let amount = self.amount();
        
        if amount < BASE_FEE_ZATOSHIS {
            return Err(FeeError::FeeTooLow(amount));
        }
        
        if amount > MAX_FEE_ZATOSHIS {
            return Err(FeeError::FeeTooHigh(amount, MAX_FEE_ZATOSHIS));
        }
        
        Ok(())
    }
}

/// Transaction balance with fee accounting
#[derive(Clone, Debug)]
pub struct TransactionBalance {
    /// Total shielded inputs
    pub shielded_input: u64,
    
    /// Total shielded outputs
    pub shielded_output: u64,
    
    /// Total transparent inputs
    pub transparent_input: u64,
    
    /// Total transparent outputs
    pub transparent_output: u64,
    
    /// Fee amount
    pub fee: u64,
}

impl TransactionBalance {
    /// Create a new balance tracker
    pub fn new() -> Self {
        Self {
            shielded_input: 0,
            shielded_output: 0,
            transparent_input: 0,
            transparent_output: 0,
            fee: 0,
        }
    }

    /// Add shielded input
    pub fn add_shielded_input(&mut self, amount: u64) {
        self.shielded_input += amount;
    }

    /// Add shielded output
    pub fn add_shielded_output(&mut self, amount: u64) {
        self.shielded_output += amount;
    }

    /// Add transparent input
    pub fn add_transparent_input(&mut self, amount: u64) {
        self.transparent_input += amount;
    }

    /// Add transparent output
    pub fn add_transparent_output(&mut self, amount: u64) {
        self.transparent_output += amount;
    }

    /// Set fee amount
    pub fn set_fee(&mut self, fee: u64) {
        self.fee = fee;
    }

    /// Check if transaction balances
    ///
    /// Balance equation: inputs = outputs + fee
    pub fn is_balanced(&self) -> bool {
        let total_input = self.shielded_input + self.transparent_input;
        let total_output = self.shielded_output + self.transparent_output + self.fee;
        total_input == total_output
    }

    /// Get net shielded value (input - output)
    pub fn net_shielded(&self) -> i64 {
        self.shielded_input as i64 - self.shielded_output as i64
    }

    /// Get net transparent value (input - output - fee)
    pub fn net_transparent(&self) -> i64 {
        self.transparent_input as i64 - self.transparent_output as i64 - self.fee as i64
    }

    /// Check if fee is covered
    pub fn has_sufficient_fee(&self) -> bool {
        self.fee > 0 && self.is_balanced()
    }
}

impl Default for TransactionBalance {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum FeeError {
    #[error("fee too low: {0} zatoshis (minimum: {BASE_FEE_ZATOSHIS})")]
    FeeTooLow(u64),
    
    #[error("fee too high: {0} zatoshis (maximum: {1})")]
    FeeTooHigh(u64, u64),
    
    #[error("transaction does not balance: inputs={0}, outputs={1}, fee={2}")]
    Unbalanced(u64, u64, u64),
    
    #[error("insufficient funds to pay fee: need {0}, have {1}")]
    InsufficientFunds(u64, u64),
    
    #[error("invalid fee payment method")]
    InvalidPaymentMethod,
}

// ----------------------------- Fee Estimation -----------------------------

/// Estimate fee for a planned transaction
pub fn estimate_fee(
    num_shielded_inputs: usize,
    num_shielded_outputs: usize,
    policy: &FeePolicy,
) -> Result<u64, FeeError> {
    // Each spend = 1 action, each output = 1 action
    // But we count logical actions (spend+output pair)
    let num_actions = num_shielded_inputs.max(num_shielded_outputs);
    
    policy.calculate_fee(num_actions, 0)
}

/// Estimate fee for a bundle
pub fn estimate_bundle_fee(
    num_traditional_actions: usize,
    num_tachyactions: usize,
    policy: &FeePolicy,
) -> Result<u64, FeeError> {
    policy.calculate_fee(num_traditional_actions, num_tachyactions)
}

// ----------------------------- Helper Functions -----------------------------

/// Format amount in ZEC with decimal places
pub fn format_zatoshis(zatoshis: u64) -> String {
    let zec = zatoshis as f64 / COIN as f64;
    format!("{:.8} ZEC", zec)
}

/// Parse ZEC amount string to zatoshis
pub fn parse_zec_amount(s: &str) -> Result<u64, FeeError> {
    let s = s.trim().to_lowercase();
    let s = s.trim_end_matches("zec").trim();
    
    let value: f64 = s.parse()
        .map_err(|_| FeeError::InvalidPaymentMethod)?;
    
    if value < 0.0 {
        return Err(FeeError::InvalidPaymentMethod);
    }
    
    let zatoshis = (value * COIN as f64).round() as u64;
    
    if zatoshis > MAX_FEE_ZATOSHIS * 100 {
        return Err(FeeError::FeeTooHigh(zatoshis, MAX_FEE_ZATOSHIS));
    }
    
    Ok(zatoshis)
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_fee_base() {
        // No actions = base fee only
        let fee = calculate_fee(0, 0, 0, 0);
        assert_eq!(fee, BASE_FEE_ZATOSHIS);
    }

    #[test]
    fn test_calculate_fee_traditional() {
        // 1 Traditional Action = 2 logical actions
        let fee = calculate_fee(1, 0, 0, 0);
        assert_eq!(fee, BASE_FEE_ZATOSHIS + 2 * FEE_PER_ACTION_ZATOSHIS);
        assert_eq!(fee, 3000); // 1000 + 2*1000
    }

    #[test]
    fn test_calculate_fee_tachyaction() {
        // 1 Tachyaction = 2 logical actions
        let fee = calculate_fee(0, 1, 0, 0);
        assert_eq!(fee, BASE_FEE_ZATOSHIS + 2 * FEE_PER_ACTION_ZATOSHIS);
        assert_eq!(fee, 3000);
    }

    #[test]
    fn test_calculate_fee_mixed() {
        // 2 Traditional + 3 Tachyactions = 10 logical actions
        let fee = calculate_fee(2, 3, 0, 0);
        assert_eq!(fee, BASE_FEE_ZATOSHIS + 10 * FEE_PER_ACTION_ZATOSHIS);
        assert_eq!(fee, 11000);
    }

    #[test]
    fn test_fee_policy_standard() {
        let policy = FeePolicy::standard();
        assert_eq!(policy.fee_per_action, FEE_PER_ACTION_ZATOSHIS);
        assert_eq!(policy.base_fee, BASE_FEE_ZATOSHIS);
    }

    #[test]
    fn test_fee_policy_high_priority() {
        let policy = FeePolicy::high_priority();
        assert_eq!(policy.fee_per_action, FEE_PER_ACTION_ZATOSHIS * 2);
        let fee = policy.calculate_fee(1, 0).unwrap();
        assert_eq!(fee, 6000); // 2000 + 2*2000
    }

    #[test]
    fn test_fee_policy_custom() {
        let policy = FeePolicy::custom(500, 500, MAX_FEE_ZATOSHIS);
        let fee = policy.calculate_fee(1, 0).unwrap();
        assert_eq!(fee, 1500); // 500 + 2*500
    }

    #[test]
    fn test_fee_payment_amount() {
        let payment = FeePayment::FromTransparent { amount: 5000 };
        assert_eq!(payment.amount(), 5000);
    }

    #[test]
    fn test_fee_payment_validation() {
        let valid = FeePayment::FromTransparent { amount: 5000 };
        assert!(valid.validate().is_ok());

        let too_low = FeePayment::FromTransparent { amount: 500 };
        assert!(too_low.validate().is_err());

        let too_high = FeePayment::FromTransparent { amount: MAX_FEE_ZATOSHIS + 1 };
        assert!(too_high.validate().is_err());
    }

    #[test]
    fn test_transaction_balance() {
        let mut balance = TransactionBalance::new();
        
        // Add 1 ZEC shielded input
        balance.add_shielded_input(COIN);
        
        // Add 0.9 ZEC shielded output
        balance.add_shielded_output(COIN * 9 / 10);
        
        // Set fee to 0.1 ZEC
        balance.set_fee(COIN / 10);
        
        // Should balance
        assert!(balance.is_balanced());
        assert!(balance.has_sufficient_fee());
    }

    #[test]
    fn test_transaction_balance_unbalanced() {
        let mut balance = TransactionBalance::new();
        balance.add_shielded_input(COIN);
        balance.add_shielded_output(COIN * 9 / 10);
        // Fee missing!
        
        assert!(!balance.is_balanced());
    }

    #[test]
    fn test_estimate_fee() {
        let policy = FeePolicy::standard();
        
        // 2 inputs, 2 outputs = 2 logical actions
        let fee = estimate_fee(2, 2, &policy).unwrap();
        assert_eq!(fee, 5000); // 1000 + 2*2*1000
    }

    #[test]
    fn test_format_zatoshis() {
        assert_eq!(format_zatoshis(COIN), "1.00000000 ZEC");
        assert_eq!(format_zatoshis(COIN / 2), "0.50000000 ZEC");
        assert_eq!(format_zatoshis(12345), "0.00012345 ZEC");
    }

    #[test]
    fn test_parse_zec_amount() {
        assert_eq!(parse_zec_amount("1.0").unwrap(), COIN);
        assert_eq!(parse_zec_amount("0.5 ZEC").unwrap(), COIN / 2);
        assert_eq!(parse_zec_amount("2.5").unwrap(), COIN * 5 / 2);
        assert_eq!(parse_zec_amount("0.00012345").unwrap(), 12345);
    }

    #[test]
    fn test_net_values() {
        let mut balance = TransactionBalance::new();
        balance.add_shielded_input(COIN);
        balance.add_shielded_output(COIN * 6 / 10);
        balance.add_transparent_output(COIN * 3 / 10);
        balance.set_fee(COIN / 10);
        
        assert_eq!(balance.net_shielded(), (COIN * 4 / 10) as i64);
        assert_eq!(balance.net_transparent(), -((COIN * 4 / 10) as i64));
        assert!(balance.is_balanced());
    }

    #[test]
    fn test_fee_policy_max_exceeded() {
        let policy = FeePolicy::custom(1000, 1000, 10000);
        
        // 100 actions would exceed max
        let result = policy.calculate_fee(100, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_sufficient() {
        let policy = FeePolicy::standard();
        
        // 2 actions requires 5000 zatoshis
        assert!(policy.is_sufficient(5000, 2));
        assert!(policy.is_sufficient(6000, 2));
        assert!(!policy.is_sufficient(4999, 2));
    }
}

