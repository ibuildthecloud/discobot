import assert from "node:assert/strict";
import test from "node:test";

import {
	parseBulkEnvVarPaste,
	parseEnvVarAssignment,
	unquoteEnvVarValue,
} from "./credentials-manager-env-vars";

test("unquoteEnvVarValue unwraps quoted values", () => {
	assert.equal(unquoteEnvVarValue('"value"'), "value");
	assert.equal(unquoteEnvVarValue("'value'"), "value");
	assert.equal(unquoteEnvVarValue('"line\\nnext"'), "line\nnext");
	assert.equal(unquoteEnvVarValue("plain"), "plain");
});

test("parseEnvVarAssignment trims export prefixes and validates keys", () => {
	assert.deepEqual(parseEnvVarAssignment("export FOO=bar"), {
		key: "FOO",
		value: "bar",
	});
	assert.deepEqual(parseEnvVarAssignment(' BAR = "baz" '), {
		key: "BAR",
		value: "baz",
	});
	assert.equal(parseEnvVarAssignment("1BAD=value"), null);
	assert.equal(parseEnvVarAssignment("not an assignment"), null);
});

test("parseBulkEnvVarPaste parses newline-separated env assignments", () => {
	assert.deepEqual(
		parseBulkEnvVarPaste("export FOO=bar\nBAR=\"baz\"\n# comment\nBAZ='qux'\n"),
		[
			{ key: "FOO", value: "bar" },
			{ key: "BAR", value: "baz" },
			{ key: "BAZ", value: "qux" },
		],
	);
});

test("parseBulkEnvVarPaste returns empty when paste is not fully parseable", () => {
	assert.deepEqual(parseBulkEnvVarPaste("FOO=bar"), []);
	assert.deepEqual(parseBulkEnvVarPaste("FOO=bar\nnot valid\nBAR=baz"), []);
});

test("parseBulkEnvVarPaste handles CRLF input", () => {
	assert.deepEqual(parseBulkEnvVarPaste("FOO=bar\r\nBAR=baz\r\n"), [
		{ key: "FOO", value: "bar" },
		{ key: "BAR", value: "baz" },
	]);
});
