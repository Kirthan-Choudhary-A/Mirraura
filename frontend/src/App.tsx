import { useState } from "react";
import { UploadPanel } from "./components/UploadPanel";
import type { Verdict } from "./types";

function App() {
  const [lastVerdict, setLastVerdict] = useState<Verdict | null>(null);

  return (
    <div>
      <h1>Mirraura</h1>
      <UploadPanel onVerdict={setLastVerdict} />
      {lastVerdict && (
        <pre>{JSON.stringify(lastVerdict, null, 2)}</pre>
      )}
    </div>
  );
}

export default App;
