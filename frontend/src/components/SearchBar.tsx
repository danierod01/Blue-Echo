import { useState, useRef, type FormEvent } from "react";
import { Search, Upload, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface Props {
  onScanIoc: (ioc: string) => void;
  onScanFile: (file: File) => void;
  loading: boolean;
}

const PLACEHOLDER_EXAMPLES = [
  "185.220.101.45",
  "d41d8cd98f00b204e9800998ecf8427e",
  "malware.evil.com",
  "https://evil.com/payload.exe",
];

export default function SearchBar({ onScanIoc, onScanFile, loading }: Props) {
  const [value, setValue] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const placeholder =
    PLACEHOLDER_EXAMPLES[Math.floor(Date.now() / 5000) % PLACEHOLDER_EXAMPLES.length];

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = value.trim();
    if (trimmed) onScanIoc(trimmed);
  }

  function handleFile(file: File | undefined) {
    if (file) onScanFile(file);
  }

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div
        className={cn(
          "flex items-center gap-2 rounded-xl border bg-gray-900 px-4 py-3 transition",
          dragOver ? "border-blue-400" : "border-gray-700 focus-within:border-blue-500"
        )}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          handleFile(e.dataTransfer.files[0]);
        }}
      >
        <Search size={18} className="shrink-0 text-gray-500" />

        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={`Introduce un IOC: ${placeholder}`}
          disabled={loading}
          className="flex-1 bg-transparent text-sm text-gray-100 placeholder-gray-600 outline-none disabled:opacity-50"
        />

        {/* Botón subir fichero */}
        <button
          type="button"
          disabled={loading}
          onClick={() => fileRef.current?.click()}
          className="shrink-0 rounded-lg p-1.5 text-gray-500 hover:bg-gray-800 hover:text-gray-300 disabled:opacity-40"
          title="Subir fichero de logs"
        >
          <Upload size={16} />
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".log,.txt,.csv,.json"
          className="hidden"
          onChange={(e) => handleFile(e.target.files?.[0])}
        />

        {/* Botón escanear */}
        <button
          type="submit"
          disabled={loading || !value.trim()}
          className="shrink-0 rounded-lg bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed transition"
        >
          {loading ? (
            <Loader2 size={16} className="animate-spin" />
          ) : (
            "Escanear"
          )}
        </button>
      </div>

      {dragOver && (
        <p className="mt-2 text-center text-xs text-blue-400">
          Suelta el fichero de logs para escanear
        </p>
      )}
    </form>
  );
}
