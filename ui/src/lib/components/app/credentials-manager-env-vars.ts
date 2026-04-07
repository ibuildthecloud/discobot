export type BulkEnvVarPaste = {
	key: string;
	value: string;
};

export function unquoteEnvVarValue(value: string): string {
	const trimmed = value.trim();
	if (trimmed.length < 2) {
		return trimmed;
	}
	const quote = trimmed[0];
	if ((quote !== '"' && quote !== "'") || trimmed.at(-1) !== quote) {
		return trimmed;
	}
	const inner = trimmed.slice(1, -1);
	if (quote === '"') {
		return inner.replace(/\\([\\"nrt$`])/g, (_match, escaped: string) => {
			switch (escaped) {
				case "n":
					return "\n";
				case "r":
					return "\r";
				case "t":
					return "\t";
				default:
					return escaped;
			}
		});
	}
	return inner;
}

export function parseEnvVarAssignment(line: string): BulkEnvVarPaste | null {
	const trimmed = line.trim();
	if (!trimmed || trimmed.startsWith("#")) {
		return null;
	}
	const withoutExport = trimmed.replace(/^export\s+/, "");
	const separatorIndex = withoutExport.indexOf("=");
	if (separatorIndex <= 0) {
		return null;
	}
	const key = withoutExport.slice(0, separatorIndex).trim();
	if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
		return null;
	}
	const value = unquoteEnvVarValue(withoutExport.slice(separatorIndex + 1));
	return { key, value };
}

export function parseBulkEnvVarPaste(value: string): BulkEnvVarPaste[] {
	const normalized = value.replace(/\r\n?/g, "\n");
	if (!normalized.includes("\n")) {
		return [];
	}
	const lines = normalized
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && !line.startsWith("#"));
	if (lines.length < 2) {
		return [];
	}
	const entries = lines.map(parseEnvVarAssignment);
	if (entries.some((entry) => entry === null)) {
		return [];
	}
	return entries as BulkEnvVarPaste[];
}
