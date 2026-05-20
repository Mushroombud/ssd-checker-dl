import json
import os
import re
import sys
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parents[1] / ".packages"
if PACKAGE_DIR.exists():
    sys.path.insert(0, str(PACKAGE_DIR))

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


class Solver:
    def __init__(self):
        self.model_name = os.environ.get("MODEL_NAME", "Qwen/Qwen3.5-0.8B")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_name,
            trust_remote_code=True,
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            torch_dtype=torch.bfloat16 if self.device.type == "cuda" else torch.float32,
            trust_remote_code=True,
        ).to(self.device)
        self.model.eval()

        print(f"solver_model={self.model_name}")
        print(f"solver_device={self.device}")

    def predict(self, dataset):
        """Predict labels for the full dataset.

        dataset: list of {"id": str, "steps": list[dict]}.
        returns: dict mapping id -> "pass" or "fail".

        Override this method to do cross-trajectory inference, retrieval
        over the whole dataset, or batched generation. The baseline just
        loops case-by-case via predict_one.
        """
        predictions = {}
        for item in dataset:
            predictions[item["id"]] = self.predict_one(item["steps"])
        return predictions

    def predict_one(self, steps):
        if not steps:
            return "fail"

        prompt = self.make_prompt(steps)
        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=2048,
        ).to(self.device)

        with torch.inference_mode():
            output_ids = self.model.generate(
                **inputs,
                do_sample=True,
                max_new_tokens=128,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        new_ids = output_ids[0, inputs["input_ids"].shape[-1]:]
        text = self.tokenizer.decode(new_ids, skip_special_tokens=True).strip().lower()
        return self.parse_answer(text)

    def make_prompt(self, steps):
        recent_steps = steps[-3:]
        content = json.dumps(recent_steps, ensure_ascii=False, indent=2)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a strict protocol judge. "
                    "Given command/response steps, decide whether the final response is valid. "
                    "Answer with exactly one word: pass or fail."
                ),
            },
            {
                "role": "user",
                "content": f"Command/response steps:\n{content}\n\nAnswer:",
            },
        ]

        if getattr(self.tokenizer, "chat_template", None):
            return self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

        system = messages[0]["content"]
        user = messages[1]["content"]
        return f"System: {system}\nUser: {user}\nAssistant:"

    def parse_answer(self, text):
        print(text)
        if re.search(r"\bpass\b", text):
            return "pass"
        if re.search(r"\bfail\b", text):
            return "fail"
        return "fail"
