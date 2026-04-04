//! Recursive descent parser for SIGMA condition strings.
//!
//! SIGMA conditions use a simple boolean grammar over selection names, with
//! support for quantifiers (`1 of`, `all of`), pipe aggregations (`| count()`),
//! and `near` expressions.
//!
//! # Grammar
//!
//! ```text
//! expr        := or_expr
//! or_expr     := and_expr ('or' and_expr)*
//! and_expr    := not_expr ('and' not_expr)*
//! not_expr    := 'not' not_expr | pipe_expr
//! pipe_expr   := primary ('|' count_op)?
//! primary     := '(' expr ')' | quantifier | selection_ref
//! quantifier  := ('1 of' | 'all of' | 'any of') selection_pattern
//! count_op    := 'count()' cmp_op number
//! cmp_op      := '>' | '>=' | '<' | '<=' | '='
//! ```

use crate::error::StreamError;
use crate::sigma::ast::{CmpOp, ConditionExpr};

/// Parses a SIGMA condition string into a [`ConditionExpr`] tree.
///
/// # Errors
///
/// Returns [`StreamError::InvalidCondition`] if the condition string uses
/// unsupported syntax or cannot be parsed.
pub fn parse_condition(condition: &str, rule_id: &str) -> Result<ConditionExpr, StreamError> {
    let tokens = tokenize(condition);
    let mut parser = ConditionParser::new(tokens, rule_id, condition);
    let expr = parser.parse_or_expr()?;

    if !parser.is_at_end() {
        return Err(StreamError::InvalidCondition {
            rule_id: rule_id.to_string(),
            condition: condition.to_string(),
        });
    }

    Ok(expr)
}

/// Tokenizes a condition string into a sequence of string tokens.
///
/// Handles quoted strings, pipe operators, parentheses, and whitespace.
fn tokenize(condition: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = condition.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' | ')' | '|' | '>' | '<' | '=' => {
                // Check for two-character operators >= <=
                chars.next();
                if (c == '>' || c == '<') && chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(format!("{c}="));
                } else {
                    tokens.push(c.to_string());
                }
            }
            _ => {
                let mut word = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == ' ' || ch == '\t' || ch == '(' || ch == ')' || ch == '|' {
                        break;
                    }
                    word.push(ch);
                    chars.next();
                }
                if !word.is_empty() {
                    tokens.push(word);
                }
            }
        }
    }

    tokens
}

/// Recursive descent parser state.
struct ConditionParser<'a> {
    tokens: Vec<String>,
    pos: usize,
    rule_id: &'a str,
    raw_condition: &'a str,
}

impl<'a> ConditionParser<'a> {
    fn new(tokens: Vec<String>, rule_id: &'a str, raw_condition: &'a str) -> Self {
        Self {
            tokens,
            pos: 0,
            rule_id,
            raw_condition,
        }
    }

    fn is_at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).map(String::as_str)
    }

    fn peek_next(&self) -> Option<&str> {
        self.tokens.get(self.pos + 1).map(String::as_str)
    }

    fn advance(&mut self) -> Option<&str> {
        let tok = self.tokens.get(self.pos).map(String::as_str);
        self.pos += 1;
        tok
    }

    fn expect_token(&mut self) -> Result<String, StreamError> {
        self.advance()
            .map(ToString::to_string)
            .ok_or_else(|| StreamError::InvalidCondition {
                rule_id: self.rule_id.to_string(),
                condition: self.raw_condition.to_string(),
            })
    }

    fn parse_or_expr(&mut self) -> Result<ConditionExpr, StreamError> {
        let mut left = self.parse_and_expr()?;

        while self.peek() == Some("or") {
            self.advance();
            let right = self.parse_and_expr()?;
            left = ConditionExpr::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_and_expr(&mut self) -> Result<ConditionExpr, StreamError> {
        let mut left = self.parse_not_expr()?;

        while self.peek() == Some("and") {
            self.advance();
            let right = self.parse_not_expr()?;
            left = ConditionExpr::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_not_expr(&mut self) -> Result<ConditionExpr, StreamError> {
        if self.peek() == Some("not") {
            self.advance();
            let inner = self.parse_not_expr()?;
            return Ok(ConditionExpr::Not(Box::new(inner)));
        }

        self.parse_pipe_expr()
    }

    fn parse_pipe_expr(&mut self) -> Result<ConditionExpr, StreamError> {
        let primary = self.parse_primary()?;

        if self.peek() == Some("|") {
            self.advance(); // consume '|'
            return self.parse_count_op(primary);
        }

        Ok(primary)
    }

    /// Parses `count() op threshold` after the pipe has been consumed.
    fn parse_count_op(&mut self, base: ConditionExpr) -> Result<ConditionExpr, StreamError> {
        // Consume 'count()' token.
        let tok = self.expect_token()?;
        if tok != "count()" {
            return Err(StreamError::InvalidCondition {
                rule_id: self.rule_id.to_string(),
                condition: self.raw_condition.to_string(),
            });
        }

        let op = self.parse_cmp_op()?;

        let threshold_str = self.expect_token()?;
        let threshold =
            threshold_str
                .parse::<u64>()
                .map_err(|_| StreamError::InvalidCondition {
                    rule_id: self.rule_id.to_string(),
                    condition: self.raw_condition.to_string(),
                })?;

        Ok(ConditionExpr::Count {
            expr: Box::new(base),
            op,
            threshold,
        })
    }

    fn parse_cmp_op(&mut self) -> Result<CmpOp, StreamError> {
        let tok = self.expect_token()?;
        match tok.as_str() {
            ">" => Ok(CmpOp::Gt),
            ">=" => Ok(CmpOp::Gte),
            "<" => Ok(CmpOp::Lt),
            "<=" => Ok(CmpOp::Lte),
            "=" => Ok(CmpOp::Eq),
            _ => Err(StreamError::InvalidCondition {
                rule_id: self.rule_id.to_string(),
                condition: self.raw_condition.to_string(),
            }),
        }
    }

    fn parse_primary(&mut self) -> Result<ConditionExpr, StreamError> {
        match self.peek() {
            Some("(") => {
                self.advance(); // consume '('
                let inner = self.parse_or_expr()?;
                if self.peek() != Some(")") {
                    return Err(StreamError::InvalidCondition {
                        rule_id: self.rule_id.to_string(),
                        condition: self.raw_condition.to_string(),
                    });
                }
                self.advance(); // consume ')'
                Ok(inner)
            }
            Some("near") => {
                self.advance();
                let inner = self.parse_primary()?;
                Ok(ConditionExpr::Near(Box::new(inner)))
            }
            // Quantifiers: look at current + next token pairs.
            Some("1") if self.peek_next() == Some("of") => {
                self.advance(); // "1"
                self.advance(); // "of"
                let pattern = self.expect_token()?;
                Ok(ConditionExpr::OneOf(pattern))
            }
            Some("any") if self.peek_next() == Some("of") => {
                self.advance(); // "any"
                self.advance(); // "of"
                let pattern = self.expect_token()?;
                Ok(ConditionExpr::OneOf(pattern))
            }
            Some("all") if self.peek_next() == Some("of") => {
                self.advance(); // "all"
                self.advance(); // "of"
                let pattern = self.expect_token()?;
                Ok(ConditionExpr::AllOf(pattern))
            }
            Some(_) => {
                let name = self.expect_token()?;
                Ok(ConditionExpr::Selection(name))
            }
            None => Err(StreamError::InvalidCondition {
                rule_id: self.rule_id.to_string(),
                condition: self.raw_condition.to_string(),
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_selection_when_parsed_then_selection_ref() {
        let expr = parse_condition("selection", "rule-1").expect("should parse");
        assert!(matches!(expr, ConditionExpr::Selection(ref s) if s == "selection"));
    }

    #[test]
    fn test_not_selection_when_parsed_then_not_node() {
        let expr = parse_condition("not selection", "rule-1").expect("should parse");
        assert!(matches!(expr, ConditionExpr::Not(_)));
        if let ConditionExpr::Not(inner) = expr {
            assert!(matches!(*inner, ConditionExpr::Selection(ref s) if s == "selection"));
        }
    }

    #[test]
    fn test_and_or_when_parsed_then_correct_tree() {
        let expr = parse_condition("sel1 and sel2 or sel3", "rule-1").expect("should parse");
        // Parsed as (sel1 and sel2) or sel3 due to precedence.
        assert!(matches!(expr, ConditionExpr::Or(_, _)));
        if let ConditionExpr::Or(left, right) = expr {
            assert!(matches!(*left, ConditionExpr::And(_, _)));
            assert!(matches!(*right, ConditionExpr::Selection(ref s) if s == "sel3"));
        }
    }

    #[test]
    fn test_one_of_when_parsed_then_quantifier() {
        let expr = parse_condition("1 of selection*", "rule-1").expect("should parse");
        assert!(matches!(expr, ConditionExpr::OneOf(ref p) if p == "selection*"));
    }

    #[test]
    fn test_count_pipe_when_parsed_then_count_node() {
        let expr = parse_condition("selection | count() > 5", "rule-1").expect("should parse");
        assert!(matches!(
            expr,
            ConditionExpr::Count {
                op: CmpOp::Gt,
                threshold: 5,
                ..
            }
        ));
    }
}
