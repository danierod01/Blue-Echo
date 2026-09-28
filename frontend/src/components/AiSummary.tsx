import { Sparkles } from "lucide-react";
import { type ReactNode } from "react";

interface Props {
  summary: string;
}

// ---------------------------------------------------------------------------
// Mini-renderizador de Markdown.
// El módulo de IA (ai_analyst.py) devuelve Markdown con encabezados `##`,
// negritas `**`, código inline `` ` `` y listas (con viñeta `-` o numeradas).
// En vez de añadir una dependencia pesada (react-markdown) para un subconjunto
// tan acotado, se parsea aquí ese subconjunto concreto.
// ---------------------------------------------------------------------------

/** Parsea el formato inline: **negrita** y `código`. */
function renderInline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  // Divide conservando los delimitadores **...** y `...`
  const tokens = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  tokens.forEach((tok, i) => {
    if (!tok) return;
    if (tok.startsWith("**") && tok.endsWith("**")) {
      nodes.push(
        <strong key={i} className="font-semibold text-gray-100">
          {tok.slice(2, -2)}
        </strong>
      );
    } else if (tok.startsWith("`") && tok.endsWith("`")) {
      nodes.push(
        <code
          key={i}
          className="font-data text-[0.8em] text-cyan-300 bg-cyan-950/40 rounded px-1 py-0.5"
        >
          {tok.slice(1, -1)}
        </code>
      );
    } else {
      nodes.push(tok);
    }
  });
  return nodes;
}

interface Block {
  type: "heading" | "para" | "ul" | "ol";
  items?: string[]; // para listas
  text?: string;    // para heading / párrafo
}

/** Agrupa las líneas del Markdown en bloques renderizables. */
function parseBlocks(md: string): Block[] {
  const lines = md.split("\n");
  const blocks: Block[] = [];
  let list: { type: "ul" | "ol"; items: string[] } | null = null;

  const flushList = () => {
    if (list) {
      blocks.push({ type: list.type, items: list.items });
      list = null;
    }
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (!line.trim()) {
      flushList();
      continue;
    }
    if (/^#{1,6}\s+/.test(line)) {
      flushList();
      blocks.push({ type: "heading", text: line.replace(/^#{1,6}\s+/, "") });
    } else if (/^[-*]\s+/.test(line)) {
      const item = line.replace(/^[-*]\s+/, "");
      if (!list || list.type !== "ul") { flushList(); list = { type: "ul", items: [] }; }
      list.items.push(item);
    } else if (/^\d+\.\s+/.test(line)) {
      const item = line.replace(/^\d+\.\s+/, "");
      if (!list || list.type !== "ol") { flushList(); list = { type: "ol", items: [] }; }
      list.items.push(item);
    } else {
      flushList();
      blocks.push({ type: "para", text: line });
    }
  }
  flushList();
  return blocks;
}

export default function AiSummary({ summary }: Props) {
  if (!summary) return null;
  const blocks = parseBlocks(summary);

  return (
    <div className="relative pl-4">
      {/* Borde izquierdo luminoso */}
      <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-gradient-to-b from-blue-400 via-cyan-400 to-transparent rounded-full" />

      <div className="flex items-center gap-2 mb-3">
        <Sparkles size={13} className="text-blue-400" />
        <span className="text-[10px] font-semibold text-blue-400 uppercase tracking-widest">
          Análisis IA
        </span>
      </div>

      <div className="space-y-3 text-sm text-gray-300 leading-relaxed">
        {blocks.map((b, i) => {
          if (b.type === "heading") {
            return (
              <h4
                key={i}
                className="text-[11px] font-semibold text-cyan-400/90 uppercase tracking-wider pt-1"
              >
                {renderInline(b.text ?? "")}
              </h4>
            );
          }
          if (b.type === "ul") {
            return (
              <ul key={i} className="space-y-1">
                {b.items!.map((it, j) => (
                  <li key={j} className="flex gap-2">
                    <span className="text-blue-500 shrink-0 mt-[3px] text-[8px]">●</span>
                    <span>{renderInline(it)}</span>
                  </li>
                ))}
              </ul>
            );
          }
          if (b.type === "ol") {
            return (
              <ol key={i} className="space-y-1">
                {b.items!.map((it, j) => (
                  <li key={j} className="flex gap-2">
                    <span className="font-data text-blue-400 shrink-0 text-xs mt-[1px]">
                      {j + 1}.
                    </span>
                    <span>{renderInline(it)}</span>
                  </li>
                ))}
              </ol>
            );
          }
          return <p key={i}>{renderInline(b.text ?? "")}</p>;
        })}
      </div>
    </div>
  );
}
