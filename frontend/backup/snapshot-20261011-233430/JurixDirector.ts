export type StagingPosture =
  | "SEATED_DESK"
  | "STAND_TRANSITION"
  | "PRESENT_HOLOGRAM"
  | "SEATED_TRANSITION";

export type GazeTarget = "CAMERA_USER" | "HOLOGRAM_DATA" | "OFFSCREEN_THINKING";

export interface ChoreographyStep {
  ptsMs: number;
  posture: StagingPosture;
  gaze: GazeTarget;
  gesture: string;
  activeNodeId?: string;
}

export interface ExecutiveLedgerMetric {
  id: string;
  label: string;
  value: string;
  delta: string;
  isAnomalous?: boolean;
}

export interface DirectorPerformancePlan {
  planId: string;
  totalDurationMs: number;
  speechText: string;
  postureSequence: ChoreographyStep[];
  hologram: {
    title: string;
    metrics: ExecutiveLedgerMetric[];
    series: { label: string; value: number }[];
  };
}

export class JurixDirector {
  private currentPlan: DirectorPerformancePlan | null = null;
  private startTime: number = 0;
  private isInterrupted: boolean = false;

  public loadPlan(plan: DirectorPerformancePlan) {
    this.currentPlan = plan;
    this.startTime = performance.now();
    this.isInterrupted = false;
  }

  public interrupt(): ChoreographyStep {
    this.isInterrupted = true;
    return {
      ptsMs: 0,
      posture: "SEATED_DESK",
      gaze: "CAMERA_USER",
      gesture: "LISTENING_RELAXED",
    };
  }

  public getCurrentState(): ChoreographyStep {
    if (!this.currentPlan || this.isInterrupted) {
      return {
        ptsMs: 0,
        posture: "SEATED_DESK",
        gaze: "CAMERA_USER",
        gesture: "IDLE_BREATHING",
      };
    }

    const elapsed = performance.now() - this.startTime;
    const steps = this.currentPlan.postureSequence;

    // Binary search/linear scan for active PTS keyframe
    let active = steps[0];
    for (let i = 0; i < steps.length; i++) {
      if (elapsed >= steps[i].ptsMs) {
        active = steps[i];
      } else {
        break;
      }
    }
    return active;
  }
}
