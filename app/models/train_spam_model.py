import pandas as pd
from sklearn.model_selection import train_test_split
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification, Trainer, TrainingArguments
import torch
from torch.utils.data import Dataset
import os

device = "cuda" if torch.cuda.is_available() else "cpu"
print("Using device:", device)

# Load dataset
df = pd.read_csv(r"C:\Users\acer\OneDrive\Desktop\threat-detection\data\CEAS_08.csv")
df["text"] = df["subject"].fillna('') + " " + df["body"].fillna('')
df = df[["text", "label"]].dropna()

# Train/test split
train_texts, val_texts, train_labels, val_labels = train_test_split(
    df["text"].tolist(), df["label"].tolist(), test_size=0.2, random_state=42
)

# Tokenization
tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
train_encodings = tokenizer(train_texts, truncation=True, padding=True, max_length=256)
val_encodings = tokenizer(val_texts, truncation=True, padding=True, max_length=256)

class SpamDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels
    def __len__(self):
        return len(self.labels)
    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item

train_dataset = SpamDataset(train_encodings, train_labels)
val_dataset = SpamDataset(val_encodings, val_labels)

# Checkpoint logic
checkpoint_dir = "app/models/bert_spam_classifier"
latest_checkpoint = None

if os.path.exists(checkpoint_dir):
    checkpoints = [d for d in os.listdir(checkpoint_dir) if d.startswith("checkpoint")]
    if checkpoints:
        latest_checkpoint = os.path.join(checkpoint_dir, sorted(checkpoints, key=lambda x: int(x.split("-")[1]))[-1])
        print(f"Resuming from checkpoint: {latest_checkpoint}")

# Load model from checkpoint or base
model_path = latest_checkpoint if latest_checkpoint else "distilbert-base-uncased"
model = DistilBertForSequenceClassification.from_pretrained(model_path, num_labels=2)

# Training arguments — stripped down for compatibility
training_args = TrainingArguments(
    output_dir=checkpoint_dir,
    num_train_epochs=3,
    per_device_train_batch_size=4,
    per_device_eval_batch_size=8,
    logging_dir="./logs",
    logging_steps=100,
    save_steps=1000,
    save_total_limit=3
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
)

# Resume training if checkpoint exists
trainer.train(resume_from_checkpoint=latest_checkpoint if latest_checkpoint else None)

# Final save
model.save_pretrained(checkpoint_dir)
tokenizer.save_pretrained(checkpoint_dir)
