import { describe, expect, test } from "bun:test";
import type { SecretsDetectionResult, SecretsMatch } from "../secrets/detect";
import type { PIIDetectionResult } from "./pii-detector";

/**
 * Pure routing logic extracted for testing
 * This mirrors the logic in Router.decideRoute()
 */
function decideRoute(
  piiResult: PIIDetectionResult,
  routing: { default: "upstream" | "local"; on_pii_detected: "upstream" | "local" },
  secretsResult?: SecretsDetectionResult,
  secretsAction?: "block" | "redact" | "route_local",
): { provider: "upstream" | "local"; reason: string } {
  // Check for secrets route_local action first (takes precedence)
  if (secretsResult?.detected && secretsAction === "route_local") {
    const secretTypes = secretsResult.matches.map((m) => m.type);
    return {
      provider: "local",
      reason: `Secrets detected (route_local): ${secretTypes.join(", ")}`,
    };
  }

  if (piiResult.hasPII) {
    const entityTypes = [...new Set(piiResult.newEntities.map((e) => e.entity_type))];
    return {
      provider: routing.on_pii_detected,
      reason: `PII detected: ${entityTypes.join(", ")}`,
    };
  }

  return {
    provider: routing.default,
    reason: "No PII detected",
  };
}

/**
 * Helper to create a mock PIIDetectionResult
 */
function createPIIResult(
  hasPII: boolean,
  entities: Array<{ entity_type: string }> = [],
): PIIDetectionResult {
  const newEntities = entities.map((e) => ({
    entity_type: e.entity_type,
    start: 0,
    end: 10,
    score: 0.9,
  }));

  return {
    hasPII,
    newEntities,
    entitiesByMessage: [newEntities],
    language: "en",
    languageFallback: false,
    scanTimeMs: 50,
  };
}

describe("decideRoute", () => {
  describe("with default=upstream, on_pii_detected=local", () => {
    const routing = { default: "upstream" as const, on_pii_detected: "local" as const };

    test("routes to upstream when no PII detected", () => {
      const result = decideRoute(createPIIResult(false), routing);

      expect(result.provider).toBe("upstream");
      expect(result.reason).toBe("No PII detected");
    });

    test("routes to local when PII detected", () => {
      const result = decideRoute(createPIIResult(true, [{ entity_type: "PERSON" }]), routing);

      expect(result.provider).toBe("local");
      expect(result.reason).toContain("PII detected");
      expect(result.reason).toContain("PERSON");
    });

    test("includes all entity types in reason", () => {
      const result = decideRoute(
        createPIIResult(true, [
          { entity_type: "PERSON" },
          { entity_type: "EMAIL_ADDRESS" },
          { entity_type: "PHONE_NUMBER" },
        ]),
        routing,
      );

      expect(result.reason).toContain("PERSON");
      expect(result.reason).toContain("EMAIL_ADDRESS");
      expect(result.reason).toContain("PHONE_NUMBER");
    });

    test("deduplicates entity types in reason", () => {
      const result = decideRoute(
        createPIIResult(true, [
          { entity_type: "PERSON" },
          { entity_type: "PERSON" },
          { entity_type: "PERSON" },
        ]),
        routing,
      );

      // Should only contain PERSON once
      const matches = result.reason.match(/PERSON/g);
      expect(matches?.length).toBe(1);
    });
  });

  describe("with default=local, on_pii_detected=upstream", () => {
    const routing = { default: "local" as const, on_pii_detected: "upstream" as const };

    test("routes to local when no PII detected", () => {
      const result = decideRoute(createPIIResult(false), routing);

      expect(result.provider).toBe("local");
      expect(result.reason).toBe("No PII detected");
    });

    test("routes to upstream when PII detected", () => {
      const result = decideRoute(
        createPIIResult(true, [{ entity_type: "EMAIL_ADDRESS" }]),
        routing,
      );

      expect(result.provider).toBe("upstream");
      expect(result.reason).toContain("PII detected");
    });
  });

  describe("with same provider for both cases", () => {
    const routing = { default: "upstream" as const, on_pii_detected: "upstream" as const };

    test("always routes to upstream regardless of PII", () => {
      expect(decideRoute(createPIIResult(false), routing).provider).toBe("upstream");
      expect(
        decideRoute(createPIIResult(true, [{ entity_type: "PERSON" }]), routing).provider,
      ).toBe("upstream");
    });
  });
});

/**
 * Helper to create a mock SecretsDetectionResult
 */
function createSecretsResult(
  detected: boolean,
  matches: SecretsMatch[] = [],
): SecretsDetectionResult {
  return {
    detected,
    matches,
    redactions: matches.map((m, i) => ({ start: i * 100, end: i * 100 + 50, type: m.type })),
  };
}

describe("decideRoute with secrets", () => {
  const routing = { default: "upstream" as const, on_pii_detected: "local" as const };

  describe("with route_local action", () => {
    test("routes to local when secrets detected", () => {
      const piiResult = createPIIResult(false);
      const secretsResult = createSecretsResult(true, [{ type: "API_KEY_OPENAI", count: 1 }]);

      const result = decideRoute(piiResult, routing, secretsResult, "route_local");

      expect(result.provider).toBe("local");
      expect(result.reason).toContain("Secrets detected");
      expect(result.reason).toContain("route_local");
      expect(result.reason).toContain("API_KEY_OPENAI");
    });

    test("secrets routing takes precedence over PII routing", () => {
      // Even with on_pii_detected=upstream, secrets route_local should go to local
      const routingUpstream = {
        default: "upstream" as const,
        on_pii_detected: "upstream" as const,
      };
      const piiResult = createPIIResult(true, [{ entity_type: "PERSON" }]);
      const secretsResult = createSecretsResult(true, [{ type: "API_KEY_AWS", count: 1 }]);

      const result = decideRoute(piiResult, routingUpstream, secretsResult, "route_local");

      expect(result.provider).toBe("local");
      expect(result.reason).toContain("Secrets detected");
    });

    test("routes based on PII when no secrets detected", () => {
      const piiResult = createPIIResult(true, [{ entity_type: "EMAIL_ADDRESS" }]);
      const secretsResult = createSecretsResult(false);

      const result = decideRoute(piiResult, routing, secretsResult, "route_local");

      expect(result.provider).toBe("local"); // PII detected -> on_pii_detected=local
      expect(result.reason).toContain("PII detected");
    });

    test("routes to default when no secrets and no PII detected", () => {
      const piiResult = createPIIResult(false);
      const secretsResult = createSecretsResult(false);

      const result = decideRoute(piiResult, routing, secretsResult, "route_local");

      expect(result.provider).toBe("upstream");
      expect(result.reason).toBe("No PII detected");
    });
  });

  describe("with block action", () => {
    test("ignores secrets detection for routing (block happens earlier)", () => {
      const piiResult = createPIIResult(false);
      const secretsResult = createSecretsResult(true, [{ type: "JWT_TOKEN", count: 1 }]);

      const result = decideRoute(piiResult, routing, secretsResult, "block");

      // With block action, we shouldn't route based on secrets
      expect(result.provider).toBe("upstream");
      expect(result.reason).toBe("No PII detected");
    });
  });

  describe("with redact action", () => {
    test("ignores secrets detection for routing (redacted before PII check)", () => {
      const piiResult = createPIIResult(false);
      const secretsResult = createSecretsResult(true, [{ type: "BEARER_TOKEN", count: 1 }]);

      const result = decideRoute(piiResult, routing, secretsResult, "redact");

      // With redact action, we route based on PII, not secrets
      expect(result.provider).toBe("upstream");
      expect(result.reason).toBe("No PII detected");
    });
  });

  describe("with multiple secret types", () => {
    test("includes all secret types in reason", () => {
      const piiResult = createPIIResult(false);
      const secretsResult = createSecretsResult(true, [
        { type: "API_KEY_OPENAI", count: 1 },
        { type: "API_KEY_GITHUB", count: 2 },
        { type: "JWT_TOKEN", count: 1 },
      ]);

      const result = decideRoute(piiResult, routing, secretsResult, "route_local");

      expect(result.reason).toContain("API_KEY_OPENAI");
      expect(result.reason).toContain("API_KEY_GITHUB");
      expect(result.reason).toContain("JWT_TOKEN");
    });
  });
});
