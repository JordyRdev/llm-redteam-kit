/**
 * OWASP Top 10 for LLM Applications 2026, and what a black-box scan can say about each risk.
 *
 * "runtime": attacks in attacks/ test it through the chat endpoint.
 * "partial": only through what you plant (a poisoned document in your knowledge base).
 * "process": cannot be seen from the outside; the report lists it as a manual check.
 */
export type OwaspId =
  | "LLM01" | "LLM02" | "LLM03" | "LLM04" | "LLM05"
  | "LLM06" | "LLM07" | "LLM08" | "LLM09" | "LLM10";

export interface OwaspRisk {
  readonly id: OwaspId;
  readonly name: string;
  readonly coverage: "runtime" | "partial" | "process";
  readonly manual?: string;
}

export const OWASP_2026: readonly OwaspRisk[] = [
  { id: "LLM01", name: "Prompt Injection", coverage: "runtime" },
  { id: "LLM02", name: "Sensitive Information Disclosure", coverage: "runtime" },
  { id: "LLM03", name: "Excessive Agency", coverage: "runtime" },
  {
    id: "LLM04", name: "Supply Chain", coverage: "process",
    manual: "Pin model, SDK and plugin versions; review third-party models, datasets and tools before use.",
  },
  { id: "LLM05", name: "Data and Model Poisoning", coverage: "partial" },
  { id: "LLM06", name: "Unbounded Consumption", coverage: "runtime" },
  { id: "LLM07", name: "Misinformation", coverage: "runtime" },
  { id: "LLM08", name: "Hidden Context Exposure", coverage: "runtime" },
  { id: "LLM09", name: "Vector and Embedding Weaknesses", coverage: "partial" },
  { id: "LLM10", name: "Improper Output Handling", coverage: "runtime" },
];

export const riskById = (id: string): OwaspRisk | undefined => OWASP_2026.find((r) => r.id === id);
