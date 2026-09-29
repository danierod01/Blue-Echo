import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import AiSummary from "@/components/AiSummary";

describe("AiSummary", () => {
  it("no renderiza nada si el resumen está vacío", () => {
    const { container } = render(<AiSummary summary="" />);
    expect(container.firstChild).toBeNull();
  });

  it("renderiza Markdown: encabezados, negritas y listas (sin dejar ## ni **)", () => {
    const md = [
      "## Resumen",
      "La IP **1.2.3.4** es **CRÍTICA**.",
      "## Hallazgos",
      "- VirusTotal: 23 motores",
      "- AbuseIPDB: 142 reportes",
    ].join("\n");

    render(<AiSummary summary={md} />);

    // Los encabezados se renderizan como texto, no como "## Resumen"
    expect(screen.getByText("Resumen")).toBeInTheDocument();
    expect(screen.getByText("Hallazgos")).toBeInTheDocument();

    // La negrita se convierte en <strong>, no queda el literal **
    const strong = screen.getByText("1.2.3.4");
    expect(strong.tagName.toLowerCase()).toBe("strong");

    // Los items de lista se renderizan
    expect(screen.getByText(/VirusTotal: 23 motores/)).toBeInTheDocument();

    // No debe quedar sintaxis Markdown cruda en el DOM
    expect(document.body.textContent).not.toContain("##");
    expect(document.body.textContent).not.toContain("**");
  });
});
