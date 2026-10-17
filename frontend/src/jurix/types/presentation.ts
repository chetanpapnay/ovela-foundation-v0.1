export type PresentationMode =
  | "idle"
  | "listening"
  | "thinking"
  | "speaking"
  | "explaining"
  | "presenting";

export interface SpeechPlan {
  text: string;
  emphasis?: string[];
  pausesMs?: number[];
}

export interface SpatialPlan {
  jurixPosition: "center" | "left" | "right";
  workspaceVisible: boolean;
  workspacePriority: "none" | "secondary" | "primary";
}

export interface GazePlan {
  target: "user" | "workspace" | "offscreen_thinking";
}

export interface GesturePlan {
  intent: "none" | "welcome" | "present_workspace" | "indicate_metric" | "enumerate";
}

export interface ExpressionPlan {
  affect: "neutral" | "warm" | "focused" | "concerned" | "serious";
  intensity: number;
}

export interface MetricItem {
  label: string;
  value: string;
  delta?: string;
}

export interface ChartSeriesItem {
  label: string;
  value: number;
}

export interface WorkspacePayload {
  type: "none" | "financial_chart" | "comparison" | "timeline" | "document";
  title?: string;
  metrics?: MetricItem[];
  series?: ChartSeriesItem[];
  summary?: string;
}

export interface JurixPresentationPlan {
  id: string;
  mode: PresentationMode;
  speech?: SpeechPlan;
  spatial: SpatialPlan;
  gaze: GazePlan;
  gesture: GesturePlan;
  expression: ExpressionPlan;
  workspace: WorkspacePayload;
  allowInterruption: boolean;
}
