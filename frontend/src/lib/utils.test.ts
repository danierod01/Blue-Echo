import { describe, it, expect } from "vitest";
import { cn, VERDICT_LABEL, formatDate } from "@/lib/utils";

describe("cn", () => {
  it("combina clases y resuelve conflictos de Tailwind", () => {
    expect(cn("p-2", "p-4")).toBe("p-4");          // twMerge: gana la última
    expect(cn("text-red-400", false, "font-bold")).toContain("font-bold");
  });
});

describe("VERDICT_LABEL", () => {
  it("mapea los veredictos al español esperado", () => {
    expect(VERDICT_LABEL.clean).toBe("LIMPIO");
    expect(VERDICT_LABEL.suspicious).toBe("SOSPECHOSO");
    expect(VERDICT_LABEL.malicious).toBe("MALICIOSO");
    expect(VERDICT_LABEL.critical).toBe("CRÍTICO");
    expect(VERDICT_LABEL.pcap).toBe("CAPTURA DE RED");
  });
});

describe("formatDate", () => {
  it("devuelve una cadena con fecha y hora a partir de un ISO", () => {
    const out = formatDate("2026-09-24T10:30:00Z");
    expect(typeof out).toBe("string");
    expect(out).toMatch(/2026/);
    expect(out).toMatch(/\d{2}:\d{2}/);
  });
});
