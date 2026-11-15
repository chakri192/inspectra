export type InputType = 'message' | 'url' | 'app_request' | 'qr_code';

export type Verdict = 'appears_safe' | 'suspicious' | 'unable_to_assess';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface AppContext {
  claimed_app_purpose: string | null;
  installation_source: string | null;
  requested_permissions: string[];
}

export interface AnalyzeRequest {
  input_type: InputType;
  content: string;
  context?: AppContext;
}

export interface Finding {
  rule_id: string;
  name: string;
  severity: Severity;
  evidence: string;
  explanation: string;
}

export interface UrlFinding {
  raw_url: string;
  domain: string;
  hostname: string;
  is_ip: boolean;
  has_suspicious_tld: boolean;
  has_homoglyphs: boolean;
  has_embedded_credentials: boolean;
  has_executable_extension: boolean;
  risk_score: number;
  findings: Finding[];
}

export interface ChecksStatus {
  text_analysis: string;
  url_structure: string;
  app_permission_analysis?: string;
  reputation: string;
  ai_semantic_analysis?: string;
  [key: string]: string | undefined;
}

export interface AnalyzeResponse {
  verdict: Verdict;
  risk_score: number;
  category: string;
  summary: string;
  findings: Finding[];
  urls: UrlFinding[];
  checks: ChecksStatus;
  limitations: string[];
  engine_version: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  engine: string;
}
