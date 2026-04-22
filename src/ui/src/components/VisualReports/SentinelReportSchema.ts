import { z } from "zod";

// --- Sentinel v3.6.1 Schema ---
export const SentinelReportSchema_v361 = z.object({
  version: z.literal("3.6.1"),
  rulepack_version: z.string(),

  context: z.object({
    analysis_mode: z.enum(["local", "sandbox"]),
    execution: z.enum(["none", "isolated"]),
    source: z.enum(["cli", "github-action"])
  }).strict(),
  
  summary: z.object({
      confidence_score: z.number().min(0).max(100),
      confidence_source: z.literal("engine")
  }).optional(),

  threats: z.number().min(0),
  filesScanned: z.number().min(0),

  rawAlerts: z.array(
    z.object({
      rule_id: z.string(),
      ruleName: z.string().optional(),
      category: z.string().optional(),
      riskLevel: z.number().min(0).max(100),
      severity: z.string(),
      description: z.string().optional(),
      explanation: z.string(),
      matched_patterns: z.array(z.string()).optional(),
      line: z.string().optional(),
      evidence: z.string().optional(),
      _file: z.string().optional(),
      _fullPath: z.string().optional(),
      _context: z.any().optional(),
      intentFingerprint: z.object({
          intent_signature: z.array(z.string()).optional()
      }).optional(),
      _rawRecord: z.object({
          metrics: z.any().optional(),
          signals: z.array(z.any()).optional(),
          hints: z.array(z.any()).optional(),
          isComposite: z.boolean().optional()
      }).optional()
    }).strict()
  ).max(10000, "Too many findings (max 10k allowed for performance)")
}).strict();

// --- Universal Dynamic Parser ---
export const Parsers: Record<string, z.ZodType<any>> = {
  "3.6.1": SentinelReportSchema_v361
};

// Types corresponding to latest schema structure 
export type SentinelReport_v361 = z.infer<typeof SentinelReportSchema_v361>;
