/**
 * Equivalents of the named pytest fixtures in the Python suite's conftest.py:
 *   balanced()      -> BalancedPolicy(raise_on_block=False)
 *   strict()        -> StrictPolicy(raise_on_block=False)
 *   logging_only()  -> LoggingOnlyPolicy()
 * Call these functions fresh in each test rather than sharing one instance,
 * since Policy is otherwise immutable/shared-safe but tests may want distinct
 * instances for `.replace()`-style mutation checks.
 */
import { BalancedPolicy, LoggingOnlyPolicy, StrictPolicy } from "../src/policies.js";

export function balancedPolicy() {
  return BalancedPolicy({ raiseOnBlock: false });
}

export function strictPolicy() {
  return StrictPolicy({ raiseOnBlock: false });
}

export function loggingOnlyPolicy() {
  return LoggingOnlyPolicy();
}
