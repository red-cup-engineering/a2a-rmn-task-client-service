#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { AGENT_CARD_PATH, AgentCard, Message, Role, Task, TaskState } from "@a2a-js/sdk";
import { ClientFactory, JsonRpcTransportFactory, RestTransportFactory, ServiceParameters, createAuthenticatingFetchWithRetry, withA2AExtensions } from "@a2a-js/sdk/client";
import { extractRmnPart } from "@red-cup-engineering/a2a-rmn-part-service";
import { discoverAgentCard, discoverSignedAgentCard } from "@red-cup-engineering/a2a-agent-card-discovery-service";

export const SOVEREIGN_CIRCUIT_INTERFACE_EXTENSION = "ni:///sha-256;wzh-zYeFQCsh4zAzGS34uacNV4qJeIEmCKIUUWyRZ-M";
const CAIP10 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/u;
export function circuitInterfaceFromAgentCard(card) {
  const accounts = [...new Set([card?.provider?.account, card?.provider?.id, card?.provider?.url]
    .filter((entry) => typeof entry === "string" && CAIP10.test(entry)))];
  if (accounts.length !== 1) throw new Error("sovereign A2A provider must expose exactly one CAIP-10 account");
  return Object.freeze({ account: accounts[0] });
}

function value(flag) { const at = process.argv.indexOf(flag); return at === -1 ? undefined : process.argv[at + 1]; }
function values(flag) { const found = []; for (let index = 0; index < process.argv.length; index += 1) if (process.argv[index] === flag) found.push(process.argv[index + 1]); return found; }
function readInput() { return JSON.parse(readFileSync(value("--input-file") ?? 0, "utf8")); }
function readBearerToken(path) {
  const bytes = readFileSync(path);
  if (bytes.length === 0 || bytes.length > 4096) throw new Error("A2A Bearer token must contain 1 through 4096 bytes");
  const token = bytes.toString("utf8").replace(/\r?\n$/u, "");
  if (!/^[A-Za-z0-9\-._~+/]+=*$/u.test(token)) throw new Error("A2A Bearer token file must contain one RFC 6750 bearer token");
  return token;
}
function bearerFetch(path) {
  if (!path) return undefined;
  const token = readBearerToken(path);
  return createAuthenticatingFetchWithRetry(fetch, {
    headers: async () => ({ Authorization: `Bearer ${token}` }),
    shouldRetryWithHeaders: async () => undefined,
  });
}
export function a2aResultParts(result) {
  if (Array.isArray(result?.parts)) return result.parts;
  if (Array.isArray(result?.status?.message?.parts)) return result.status.message.parts;
  if (Array.isArray(result?.artifacts)) return result.artifacts.flatMap((artifact) => artifact.parts ?? []);
  return [];
}
export function a2aResultMetadata(result) {
  if (Array.isArray(result?.parts)) return result.metadata ?? {};
  if (Array.isArray(result?.status?.message?.parts)) return result.status.message.metadata ?? {};
  return result?.metadata ?? {};
}
function refusal(result) {
  const text = a2aResultParts(result).find((part) => part?.content?.$case === "text")?.content?.value;
  const state = result?.status?.state;
  if (a2aResultMetadata(result).disposition === "refused"
    || [TaskState.TASK_STATE_FAILED, TaskState.TASK_STATE_CANCELED, TaskState.TASK_STATE_INPUT_REQUIRED,
      TaskState.TASK_STATE_REJECTED, TaskState.TASK_STATE_AUTH_REQUIRED].includes(state)) {
    return text ?? "A2A agent refused the RMN task";
  }
  return undefined;
}

const TERMINAL_TASK_STATES = new Set([
  TaskState.TASK_STATE_COMPLETED,
  TaskState.TASK_STATE_FAILED,
  TaskState.TASK_STATE_CANCELED,
  TaskState.TASK_STATE_INPUT_REQUIRED,
  TaskState.TASK_STATE_REJECTED,
  TaskState.TASK_STATE_AUTH_REQUIRED,
]);

export async function discoverA2aClient(agentUrl, { signal, agentCard, bearerTokenFile } = {}) {
  const authenticatedFetch = bearerFetch(bearerTokenFile);
  const factory = authenticatedFetch
    ? new ClientFactory({ transports: [new JsonRpcTransportFactory({ fetchImpl: authenticatedFetch }), new RestTransportFactory({ fetchImpl: authenticatedFetch })] })
    : new ClientFactory();
  if (agentCard) return factory.createFromAgentCard(agentCard);
  const parsedAgentUrl = new URL(agentUrl);
  const exactCard = parsedAgentUrl.pathname.endsWith(`/${AGENT_CARD_PATH}`);
  return exactCard
    ? await factory.createFromUrl(agentUrl, "")
    : await factory.createFromUrl(agentUrl);
}

/** Discover and validate the card before the exactly-once invocation. Both the
 * card and its same-origin JWKS are read-only standard resources, so a
 * transient reset may be retried without replaying customer work. */
export async function discoverValidatedAgentCard(agentUrl, { requireSignature = false, signal, discover } = {}) {
  const read = discover ?? (requireSignature ? discoverSignedAgentCard : discoverAgentCard);
  return await read({ agentUrl, signal });
}

function cardRequiresBearer(card) {
  const requirements = card.securityRequirements ?? [];
  const schemes = card.securitySchemes ?? {};
  if (requirements.length === 0) {
    if (Object.keys(schemes).length !== 0) throw new Error("A2A Agent Card declares unused security schemes");
    if ((card.skills ?? []).some((skill) => (skill.securityRequirements ?? []).length !== 0)) throw new Error("A2A skill requires security absent from its Agent Card");
    return false;
  }
  if (requirements.length !== 1) throw new Error("A2A client supports exactly one global security requirement");
  const names = Object.keys(requirements[0]?.schemes ?? {});
  if (names.length !== 1 || Object.keys(schemes).length !== 1 || !Object.hasOwn(schemes, names[0])) throw new Error("A2A client requires exactly one referenced security scheme");
  if ((card.skills ?? []).some((skill) => JSON.stringify(skill.securityRequirements ?? []) !== JSON.stringify(requirements))) throw new Error("A2A skill security must equal its Agent Card's global requirement");
  const declared = schemes[names[0]];
  const scheme = declared?.httpAuthSecurityScheme
    ?? (declared?.scheme?.$case === "httpAuthSecurityScheme" ? declared.scheme.value : undefined);
  if (!scheme || String(scheme.scheme).toLowerCase() !== "bearer") throw new Error("A2A client currently supports only standard HTTP Bearer security");
  return true;
}

async function connection(agentUrl, extensions, requireSignature, signal, bearerTokenFile) {
  const agentCard = await discoverValidatedAgentCard(agentUrl, { requireSignature, signal });
  const cardJson = AgentCard.toJSON(agentCard);
  const requiresBearer = cardRequiresBearer(cardJson);
  if (requiresBearer && !bearerTokenFile) throw new Error("A2A Agent Card requires a Bearer token file");
  if (!requiresBearer && bearerTokenFile) throw new Error("A2A Bearer token supplied to an Agent Card that does not declare Bearer security");
  const discoveryOrigin = new URL(agentUrl).origin;
  if (bearerTokenFile && cardJson.supportedInterfaces.some((face) => new URL(face.url).origin !== discoveryOrigin)) {
    throw new Error("A2A Bearer credential cannot cross the Agent Card discovery origin");
  }
  const supported = new Set([SOVEREIGN_CIRCUIT_INTERFACE_EXTENSION, ...extensions]);
  const negotiated = new Set(extensions);
  for (const extension of cardJson.capabilities?.extensions ?? []) {
    if (extension.required !== true) continue;
    if (typeof extension.uri !== "string" || !supported.has(extension.uri)) {
      throw new Error(`A2A agent requires an unsupported extension: ${String(extension.uri)}`);
    }
    negotiated.add(extension.uri);
  }
  if (negotiated.has(SOVEREIGN_CIRCUIT_INTERFACE_EXTENSION)) circuitInterfaceFromAgentCard(cardJson);
  const client = await discoverA2aClient(agentUrl, { signal, agentCard, bearerTokenFile });
  const serviceParameters = ServiceParameters.create(withA2AExtensions(...negotiated));
  return {
    agentCard: cardJson,
    authentication: {
      required: requireSignature,
      agentCardSignatureVerified: requireSignature,
    },
    client,
    extensions: [...negotiated],
    serviceParameters,
  };
}

async function observeTask(result, onTaskObservation, prior) {
  if (typeof result?.id !== "string") return prior;
  const signature = `${result.id}|${result.status?.state}|${result.status?.timestamp ?? ""}`;
  if (signature !== prior && onTaskObservation) await onTaskObservation(Task.toJSON(result));
  return signature;
}

function outboundRecordPath(root, agentUrl, inputNi) {
  if (!root) return null;
  const digest = createHash("sha256").update(`${new URL(agentUrl).href}\n${inputNi}`, "utf8").digest("hex");
  return resolve(root, digest.slice(0, 2), `${digest}.json`);
}

function readOutboundRecord(path, agentUrl, inputNi) {
  if (!path) return null;
  try {
    const record = JSON.parse(readFileSync(path, "utf8"));
    if (record.agentUrl !== new URL(agentUrl).href || record.inputNi !== inputNi || typeof record.taskId !== "string") {
      throw new Error(`outbound A2A custody record drifted at ${path}`);
    }
    return record;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function seatOutboundRecord(path, record) {
  if (!path) return;
  mkdirSync(dirname(path), { recursive: true });
  try { writeFileSync(path, `${JSON.stringify(record)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 }); }
  catch (error) {
    if (error.code !== "EEXIST") throw error;
    const seated = readOutboundRecord(path, record.agentUrl, record.inputNi);
    if (seated.taskId !== record.taskId) throw new Error(`concurrent outbound A2A submissions diverged at ${path}`);
  }
}

function dependencyPushConfiguration(taskId, callbackUrl = process.env.A2A_PARENT_CALLBACK_URL, callbackToken = process.env.A2A_PARENT_CALLBACK_TOKEN) {
  if (!callbackUrl && !callbackToken) return undefined;
  if (!callbackUrl || !callbackToken) throw new Error("A2A parent callback URL and token must be supplied together");
  const url = new URL(callbackUrl);
  if (url.protocol !== "https:") throw new Error("A2A parent callback must use HTTPS");
  const id = createHash("sha256").update(`${taskId}\n${url.href}`, "utf8").digest("hex");
  return {
    tenant: "",
    id,
    taskId,
    url: url.href,
    token: "",
    authentication: { scheme: "Bearer", credentials: callbackToken },
  };
}

function providerSupportsPush(agentCard) {
  return agentCard?.capabilities?.pushNotifications === true;
}

async function registerDependencyPush(client, taskId, serviceParameters, signal, callbackUrl, callbackToken) {
  const configuration = dependencyPushConfiguration(taskId, callbackUrl, callbackToken);
  if (!configuration) return undefined;
  return await client.createTaskPushNotificationConfig(configuration, { signal, serviceParameters });
}

export class A2aTaskPendingError extends Error {
  constructor(result, agentUrl) {
    super(`A2A task ${result?.id ?? "(unknown)"} remains nonterminal`);
    this.name = "A2aTaskPendingError";
    this.task = result;
    this.taskId = result?.id;
    this.agentUrl = agentUrl;
  }
}

function requireTerminalTask(result, agentUrl) {
  if (typeof result?.id === "string" && !TERMINAL_TASK_STATES.has(result?.status?.state)) {
    throw new A2aTaskPendingError(Task.toJSON(result), agentUrl);
  }
  return result;
}

function completedExchange(result, { inputNi, agentCard, authentication, extensions }) {
  const denied = refusal(result);
  if (denied) {
    const error = new Error(denied);
    error.result = result;
    error.inputNi = inputNi;
    throw error;
  }
  const output = extractRmnPart(a2aResultParts(result));
  return { result, inputNi, outputNi: output.ni, agentCard, authentication, extensions };
}

export async function resumeRmnTask({ agentUrl, taskId, inputNi, extensions = [], requireSignature = false, bearerTokenFile, onTaskObservation, signal }) {
  if (!agentUrl) throw new Error("agentUrl is required");
  if (typeof taskId !== "string" || taskId.length === 0) throw new Error("taskId is required");
  const linked = await connection(agentUrl, extensions, requireSignature, signal, bearerTokenFile);
  let result = await linked.client.getTask({ id: taskId, historyLength: 0 }, { signal, serviceParameters: linked.serviceParameters });
  await observeTask(result, onTaskObservation);
  result = requireTerminalTask(result, agentUrl);
  const exactInputNi = inputNi ?? a2aResultMetadata(result).inputNi;
  if (typeof exactInputNi !== "string" || !exactInputNi.startsWith("ni:///sha-256;")) throw new Error("resumed A2A task lacks its exact RMN input identity");
  return completedExchange(result, { ...linked, inputNi: exactInputNi });
}

export async function cancelRmnTask({ agentUrl, taskId, extensions = [], requireSignature = false, bearerTokenFile, onTaskObservation, signal }) {
  if (!agentUrl) throw new Error("agentUrl is required");
  if (typeof taskId !== "string" || taskId.length === 0) throw new Error("taskId is required");
  const linked = await connection(agentUrl, extensions, requireSignature, signal, bearerTokenFile);
  const result = await linked.client.cancelTask({ id: taskId }, { signal, serviceParameters: linked.serviceParameters });
  await observeTask(result, onTaskObservation);
  if (result?.id !== taskId || result?.status?.state !== TaskState.TASK_STATE_CANCELED) {
    throw new Error(`A2A provider did not witness cancellation of task ${taskId}`);
  }
  return Object.freeze({
    task: Task.toJSON(result), taskId,
    agentCard: linked.agentCard,
    authentication: linked.authentication,
    extensions: linked.extensions,
  });
}

async function submitLinkedRmnTask({ agentUrl, extensions = [], message: source, requireSignature = false, bearerTokenFile, onTaskObservation, signal, returnImmediately = true, outboundTaskRoot = process.env.A2A_OUTBOUND_TASK_ROOT, callbackUrl, callbackToken }) {
  if (!agentUrl) throw new Error("agentUrl is required");
  const message = Message.fromJSON(source);
  if (message.role !== Role.ROLE_USER) throw new Error("outbound A2A message role must be ROLE_USER");
  const input = extractRmnPart(message.parts);
  const linked = await connection(agentUrl, extensions, requireSignature, signal, bearerTokenFile);
  const custodyPath = outboundRecordPath(outboundTaskRoot, agentUrl, input.ni);
  const prior = readOutboundRecord(custodyPath, agentUrl, input.ni);
  const pushConfiguration = dependencyPushConfiguration("", callbackUrl, callbackToken);
  const initialPushConfiguration = prior || !providerSupportsPush(linked.agentCard) ? undefined : pushConfiguration;
  const result = prior
    ? await linked.client.getTask({ id: prior.taskId, historyLength: 0 }, { signal, serviceParameters: linked.serviceParameters })
    : await linked.client.sendMessage({
      message: { ...message, messageId: message.messageId || randomUUID() },
      configuration: {
        acceptedOutputModes: ["application/rmn+cbor"], taskPushNotificationConfig: initialPushConfiguration,
        historyLength: 0,
        // A provider without a push pore must carry its terminal result on the
        // same transport.  Returning a nonterminal task from that provider
        // would strand the parent with no event that can lawfully resume it.
        returnImmediately: providerSupportsPush(linked.agentCard) ? returnImmediately : false,
      },
    }, { signal, serviceParameters: linked.serviceParameters });
  if (typeof result?.id !== "string" || result.id.length === 0) throw new Error("durable A2A submission did not return an opaque task identity");
  if (!prior) seatOutboundRecord(custodyPath, { protocol: "A2A", protocolVersion: "1.0", agentUrl: new URL(agentUrl).href, inputNi: input.ni, taskId: result.id });
  if (prior && providerSupportsPush(linked.agentCard)) {
    await registerDependencyPush(linked.client, result.id, linked.serviceParameters, signal, callbackUrl, callbackToken);
  }
  await observeTask(result, onTaskObservation);
  return { input, linked, result };
}

export async function submitRmnTask(options) {
  const { input, linked, result } = await submitLinkedRmnTask(options);
  return Object.freeze({
    task: Task.toJSON(result),
    taskId: result.id,
    inputNi: input.ni,
    agentCard: linked.agentCard,
    authentication: linked.authentication,
    extensions: linked.extensions,
  });
}

export async function sendRmnTask({ agentUrl, extensions = [], message: source, requireSignature = false, bearerTokenFile, onTaskObservation, signal, callbackUrl, callbackToken }) {
  // A nested cell relinquishes its transport as soon as durable callback
  // custody exists.  A direct caller that supplied no callback explicitly
  // chose the blocking A2A operation; the provider, not a client temporal ceiling,
  // determines when that connection yields a terminal result.
  const explicitlyAcceptedCallbackCustody = callbackUrl !== undefined || callbackToken !== undefined;
  const hasCallbackPore = explicitlyAcceptedCallbackCustody
    ? dependencyPushConfiguration("", callbackUrl, callbackToken) !== undefined
    : false;
  const { input, linked, result: submitted } = await submitLinkedRmnTask({
    agentUrl, extensions, message: source, requireSignature, bearerTokenFile,
    onTaskObservation, signal,
    // Undefined means "consult ambient host configuration" to the lower-level
    // submission primitive.  A composed call has not accepted that authority,
    // so pass explicit nulls unless its caller supplied the callback pair.
    callbackUrl: explicitlyAcceptedCallbackCustody ? callbackUrl : null,
    callbackToken: explicitlyAcceptedCallbackCustody ? callbackToken : null,
    returnImmediately: hasCallbackPore,
  });
  if (typeof submitted?.id === "string"
    && !TERMINAL_TASK_STATES.has(submitted?.status?.state)
    && !providerSupportsPush(linked.agentCard)
    && (process.env.A2A_PARENT_CALLBACK_URL || process.env.A2A_PARENT_CALLBACK_TOKEN)) {
    const error = new A2aTaskPendingError(submitted, agentUrl);
    error.obstruction = "provider-does-not-advertise-push-notifications";
    throw error;
  }
  const result = requireTerminalTask(submitted, agentUrl);
  return completedExchange(result, { ...linked, inputNi: input.ni });
}

if (process.argv[1] && process.argv[1].endsWith("send-rmn-task.mjs")) {
  if (value("--timeout-ms") !== undefined) throw new Error("--timeout-ms is retired; use A2A task cancellation");
  sendRmnTask({ agentUrl: value("--agent"), extensions: values("--extension"), bearerTokenFile: value("--bearer-token-file"), message: readInput() })
    .then(({ result, inputNi, outputNi }) => {
      const outputFile = value("--output-file"), receiptFile = value("--receipt-file");
      const output = `${JSON.stringify(Array.isArray(result?.parts) ? Message.toJSON(result) : Task.toJSON(result))}\n`;
      if (outputFile) writeFileSync(outputFile, output, "utf8"); else process.stdout.write(output);
      if (receiptFile) writeFileSync(receiptFile, `${JSON.stringify({ protocol: "A2A", protocolVersion: "1.0", inputNi, outputNi })}\n`, "utf8");
    })
    .catch((error) => { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; });
}
