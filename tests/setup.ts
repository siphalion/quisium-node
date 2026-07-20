import { afterEach, beforeEach } from "vitest";
import { clearHandlers } from "../src/logging.js";

// Mirrors the Python suite's autouse `_clean_handlers` fixture in conftest.py.
beforeEach(() => {
  clearHandlers();
});

afterEach(() => {
  clearHandlers();
});
