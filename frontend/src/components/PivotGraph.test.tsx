import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import PivotGraph from "@/components/PivotGraph";
import type { PivotEntity } from "@/api/client";

const pivots: PivotEntity[] = [
  { value: "1.2.3.4", ioc_type: "ipv4", relation: "domain→ip", source: "geolocation" },
  { value: "ns1.evil.com", ioc_type: "domain", relation: "domain→nameserver", source: "rdap" },
];

describe("PivotGraph", () => {
  it("dibuja el nodo central y un nodo por pivote, con leyenda por relación", () => {
    render(
      <PivotGraph centerValue="evil.com" centerType="domain" pivots={pivots} onScan={() => {}} />,
    );
    // Nodo central
    expect(screen.getByText("evil.com")).toBeInTheDocument();
    // Un nodo por pivote (el texto del valor aparece)
    expect(screen.getByText("1.2.3.4")).toBeInTheDocument();
    expect(screen.getByText("ns1.evil.com")).toBeInTheDocument();
    // Leyenda: la identidad no es solo color, la relación aparece como texto
    expect(screen.getByText("domain→ip")).toBeInTheDocument();
    expect(screen.getByText("domain→nameserver")).toBeInTheDocument();
  });

  it("al hacer clic en un nodo pivote lanza onScan con su valor", () => {
    const onScan = vi.fn();
    render(
      <PivotGraph centerValue="evil.com" centerType="domain" pivots={pivots} onScan={onScan} />,
    );
    fireEvent.click(screen.getByText("1.2.3.4"));
    expect(onScan).toHaveBeenCalledWith("1.2.3.4");
  });
});
