export default function SkeletonResults() {
  return (
    <div className="flex flex-col gap-6 animate-pulse">
      {/* Score + Table row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-start">
        {/* Score card */}
        <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-6 flex flex-col items-center gap-4">
          <div className="w-36 h-36 rounded-full border-[10px] border-gray-800" />
          <div className="h-5 w-24 bg-gray-800 rounded-full" />
          <div className="h-4 w-32 bg-gray-800 rounded" />
        </div>

        {/* Connector cards */}
        <div className="md:col-span-2 flex flex-col gap-3">
          {[1, 2, 3].map((g) => (
            <div key={g} className="rounded-2xl border border-gray-800 bg-gray-900/50 p-4 flex flex-col gap-2">
              <div className="h-3 w-32 bg-gray-800 rounded mb-1" />
              {[1, 2, 3].map((r) => (
                <div key={r} className="flex items-center gap-3 rounded-xl border border-gray-800/60 bg-gray-900/30 px-4 py-3">
                  <div className="w-4 h-4 rounded-full bg-gray-800 shrink-0" />
                  <div className="flex-1 space-y-1.5">
                    <div className="h-3 w-24 bg-gray-800 rounded" />
                    <div className="h-2.5 w-36 bg-gray-800/60 rounded" />
                  </div>
                  <div className="h-3 w-10 bg-gray-800 rounded" />
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* AI Summary skeleton */}
      <div className="rounded-2xl border border-blue-900/30 bg-gray-900/50 p-5 space-y-3">
        <div className="h-3 w-40 bg-gray-800 rounded" />
        <div className="h-3 w-full bg-gray-800/60 rounded" />
        <div className="h-3 w-5/6 bg-gray-800/60 rounded" />
        <div className="h-3 w-4/6 bg-gray-800/60 rounded" />
      </div>
    </div>
  );
}
