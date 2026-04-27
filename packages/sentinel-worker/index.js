import express from "express";
import { exec } from "child_process";

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Analyzer activo 🚀");
});

app.post("/analyze", async (req, res) => {
  const { repo } = req.body;

  console.log("Analizando:", repo);

  // Simulación (luego metes tu motor real de Sentinel)
  const result = {
    repo,
    vulnerabilities: Math.floor(Math.random() * 1000),
    status: "done"
  };

  res.json(result);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
