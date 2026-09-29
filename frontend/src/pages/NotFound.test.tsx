import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import NotFound from "@/pages/NotFound";

describe("NotFound", () => {
  it("muestra el 404 y un enlace de vuelta al panel", () => {
    render(
      <MemoryRouter>
        <NotFound />
      </MemoryRouter>
    );
    expect(screen.getByText("404")).toBeInTheDocument();
    expect(screen.getByText(/no encontrada/i)).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /volver al panel/i });
    expect(link).toHaveAttribute("href", "/");
  });
});
