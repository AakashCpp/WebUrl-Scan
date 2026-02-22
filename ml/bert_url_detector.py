# ml/bert_url_detector.py

import torch
from transformers import BertTokenizer, BertForSequenceClassification
from huggingface_hub import hf_hub_download # Naya import

class BertURLDetector:
    def __init__(self):
        print("Initializing Blackhole Phishing Detector...")
        print("Loading URL model from Hugging Face Hub...")
        
        # Hugging Face repository details
        repo_id = "skyGaze/URLmodel"
        filename = "URLmodel.pth"

        # Model ko Hub se download/cache karna (Local path ki jagah yeh use hoga)
        model_path = hf_hub_download(repo_id=repo_id, filename=filename)
        
        print("Model loaded successfully! Setting up BERT...")

        self.tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
        self.model = BertForSequenceClassification.from_pretrained(
            "bert-base-uncased",
            num_labels=2
        )

        # Downloaded/Cached model file ko PyTorch mein load kar rahe hain
        self.model.load_state_dict(
            torch.load(model_path, map_location=torch.device("cpu"), weights_only=True)
        )

        self.model.eval()
        print("Detector is ready to scan URLs! 🚀")

    def predict(self, url: str) -> dict:
        inputs = self.tokenizer(
            url,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        )

        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)
            confidence, prediction = torch.max(probs, dim=1)

        label = "phishing" if prediction.item() == 1 else "legitimate"

        return {
            "label": label,
            "confidence": round(confidence.item(), 4)
        }