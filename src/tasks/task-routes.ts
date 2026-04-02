import type { IncomingMessage, ServerResponse } from "http";
import { hostCommandErrorResponse, json, readJson } from "../http/common.js";
import type { RelayStore } from "../store.js";
import {
  buildCronTaskMutationParams,
  buildTaskRecordFromCronResponse,
  computeNextTaskRun,
  normalizeTaskBody,
  sortTaskRecords,
  type TaskRecord,
} from "./task-utils.js";
import type { GatewayMembershipRecord, GatewayRuntimeStateRecord } from "../types.js";
import type { PendingTaskRun } from "../ws/runtime-types.js";

export interface TaskRouteHandlers {
  handleGatewayTasks: (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
  handleGatewayTask: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    taskIdValue: string,
  ) => Promise<void>;
  listGatewayTasksForMobile: (gatewayIdValue: string, userId: string) => TaskRecord[];
}

export interface TaskRouteOptions {
  store: RelayStore;
  nowIso: () => string;
  persist: () => Promise<void>;
  schedulePersist: (delayMs?: number) => void;
  scheduleTaskSweep: (delayMs?: number) => void;
  requireAuthenticatedUser: (req: IncomingMessage, res: ServerResponse) => string | null;
  getMembership: (gatewayIdValue: string, userId: string) => GatewayMembershipRecord | undefined;
  dispatchHostCommand: (gatewayIdValue: string, userId: string, method: string, params: unknown) => Promise<unknown>;
  touchGateway: (gatewayIdValue: string, patch: Partial<GatewayRuntimeStateRecord>) => void;
  broadcastTaskUpdate: (gatewayIdValue: string, taskId: string, event?: string) => void;
  pendingTaskRunsByTaskID: Map<string, PendingTaskRun>;
}

export function createTaskRouteHandlers(options: TaskRouteOptions): TaskRouteHandlers {
  const markGatewayHealthy = (gatewayIdValue: string): void => {
    options.touchGateway(gatewayIdValue, {
      relayStatus: "relay_connected",
      hostStatus: "healthy",
      openclawStatus: "healthy",
      lastSeenAt: options.nowIso(),
    });
    options.schedulePersist();
  };

  const listGatewayTasksForMobile = (gatewayIdValue: string, _userId: string): TaskRecord[] => {
    return sortTaskRecords(options.store.tasksForGateway(gatewayIdValue));
  };

  const handleGatewayTasks = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }

    if (req.method === "GET") {
      try {
        const items = listGatewayTasksForMobile(gatewayIdValue, userId);
        markGatewayHealthy(gatewayIdValue);
        json(res, 200, { items });
      } catch (error) {
        const response = hostCommandErrorResponse(error);
        json(res, response.status, response.body);
      }
      return;
    }

    if (membership.role === "viewer") {
      json(res, 403, { error: "forbidden" });
      return;
    }

    const body = (await readJson<Record<string, unknown>>(req)) ?? {};

    if (req.method === "POST") {
      const normalized = normalizeTaskBody(body);
      if (normalized.error) {
        json(res, 400, { error: normalized.error });
        return;
      }
      const mutationParams = buildCronTaskMutationParams(normalized);
      if (!mutationParams) {
        json(res, 400, { error: "invalid_request" });
        return;
      }

      try {
        const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "cron.add", mutationParams);
        markGatewayHealthy(gatewayIdValue);
        const task = buildTaskRecordFromCronResponse(gatewayIdValue, userId, payload);
        if (!task) {
          json(res, 502, { error: "invalid_cron_response" });
          return;
        }
        options.broadcastTaskUpdate(gatewayIdValue, task.id);
        json(res, 200, { task });
      } catch (error) {
        const response = hostCommandErrorResponse(error);
        json(res, response.status, response.body);
      }
      return;
    }

    json(res, 405, { error: "method_not_allowed" });
  };

  const handleGatewayTask = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    taskIdValue: string,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }

    const legacyTask = options.store.snapshot().tasks[taskIdValue];
    if (legacyTask && legacyTask.gatewayId !== gatewayIdValue) {
      json(res, 404, { error: "task_not_found" });
      return;
    }
    if (legacyTask && legacyTask.gatewayId === gatewayIdValue) {
      if (req.method === "DELETE") {
        if (membership.role === "viewer") {
          json(res, 403, { error: "forbidden" });
          return;
        }
        const pending = options.pendingTaskRunsByTaskID.get(taskIdValue);
        if (pending) {
          clearTimeout(pending.timeout);
          options.pendingTaskRunsByTaskID.delete(taskIdValue);
        }
        options.store.removeTask(taskIdValue);
        await options.persist();
        options.broadcastTaskUpdate(gatewayIdValue, taskIdValue);
        options.scheduleTaskSweep(0);
        json(res, 200, { ok: true });
        return;
      }

      if (req.method !== "PATCH") {
        json(res, 405, { error: "method_not_allowed" });
        return;
      }

      if (membership.role === "viewer") {
        json(res, 403, { error: "forbidden" });
        return;
      }
      const body = (await readJson<Record<string, unknown>>(req)) ?? {};
      const normalized = normalizeTaskBody(body, legacyTask);
      if (normalized.error) {
        json(res, 400, { error: normalized.error });
        return;
      }

      legacyTask.title = normalized.title;
      legacyTask.prompt = normalized.prompt;
      legacyTask.scheduleKind = normalized.scheduleKind;
      legacyTask.scheduleAt = normalized.scheduleAt;
      legacyTask.repeatAmount = normalized.repeatAmount;
      legacyTask.repeatUnit = normalized.repeatUnit;
      legacyTask.enabled = normalized.enabled;

      const scheduleFieldsChanged =
        body.title !== undefined ||
        body.prompt !== undefined ||
        body.scheduleKind !== undefined ||
        body.scheduleAt !== undefined ||
        body.repeatAmount !== undefined ||
        body.repeatUnit !== undefined;
      if (scheduleFieldsChanged || legacyTask.enabled) {
        legacyTask.nextRunAt = computeNextTaskRun(legacyTask, new Date());
      }
      legacyTask.updatedAt = options.nowIso();
      options.store.putTask(legacyTask);
      await options.persist();
      options.broadcastTaskUpdate(gatewayIdValue, legacyTask.id);
      options.scheduleTaskSweep(0);
      json(res, 200, { task: legacyTask });
      return;
    }

    if (req.method === "DELETE") {
      if (membership.role === "viewer") {
        json(res, 403, { error: "forbidden" });
        return;
      }
      try {
        const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "cron.remove", {
          id: taskIdValue,
        });
        markGatewayHealthy(gatewayIdValue);
        const result = payload && typeof payload === "object" && !Array.isArray(payload)
          ? (payload as { removed?: unknown })
          : undefined;
        if (result?.removed === false) {
          json(res, 404, { error: "task_not_found" });
          return;
        }
        options.broadcastTaskUpdate(gatewayIdValue, taskIdValue, "task_updated");
        json(res, 200, { ok: true });
      } catch (error) {
        const response = hostCommandErrorResponse(error);
        json(res, response.status, response.body);
      }
      return;
    }

    if (req.method !== "PATCH") {
      json(res, 405, { error: "method_not_allowed" });
      return;
    }

    if (membership.role === "viewer") {
      json(res, 403, { error: "forbidden" });
      return;
    }

    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const enabledOnlyPatch =
      typeof body.enabled === "boolean" &&
      Object.keys(body).every((key) => key === "enabled");

    if (enabledOnlyPatch) {
      try {
        const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "cron.update", {
          id: taskIdValue,
          patch: { enabled: body.enabled },
        });
        markGatewayHealthy(gatewayIdValue);
        const task = buildTaskRecordFromCronResponse(gatewayIdValue, userId, payload);
        if (!task) {
          json(res, 502, { error: "invalid_cron_response" });
          return;
        }
        options.broadcastTaskUpdate(gatewayIdValue, task.id);
        json(res, 200, { task });
      } catch (error) {
        const response = hostCommandErrorResponse(error);
        json(res, response.status, response.body);
      }
      return;
    }

    const normalized = normalizeTaskBody(body);
    if (normalized.error) {
      json(res, 400, { error: normalized.error });
      return;
    }

    const patch = buildCronTaskMutationParams(normalized);
    if (!patch) {
      json(res, 400, { error: "invalid_request" });
      return;
    }

    try {
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "cron.update", {
        id: taskIdValue,
        patch,
      });
      markGatewayHealthy(gatewayIdValue);
      const task = buildTaskRecordFromCronResponse(gatewayIdValue, userId, payload);
      if (!task) {
        json(res, 502, { error: "invalid_cron_response" });
        return;
      }
      options.broadcastTaskUpdate(gatewayIdValue, task.id);
      json(res, 200, { task });
    } catch (error) {
      const response = hostCommandErrorResponse(error);
      json(res, response.status, response.body);
    }
  };

  return {
    handleGatewayTasks,
    handleGatewayTask,
    listGatewayTasksForMobile,
  };
}
