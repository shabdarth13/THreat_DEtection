import os
import pandas as pd
import torch

from sklearn.model_selection import train_test_split
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments
)


# ------------------ PATH SETUP ------------------

CURRENT_FILE_DIR = os.path.dirname(os.path.abspath(__file__))

# app/models -> app -> project root
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_FILE_DIR, "..", ".."))

DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "CEAS_08.csv")

CHECKPOINT_DIR = os.path.join(
    PROJECT_ROOT,
    "app",
    "models",
    "bert_spam_classifier"
)

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

os.makedirs(CHECKPOINT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)


# ------------------ DEVICE ------------------

device = "cuda" if torch.cuda.is_available() else "cpu"
print("Using device:", device)
print("Dataset path:", DATASET_PATH)
print("Model save path:", CHECKPOINT_DIR)


# ------------------ LOAD DATASET ------------------

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(f"Dataset not found at: {DATASET_PATH}")
    
df = pd.read_csv(
    DATASET_PATH,
    engine="python",
    on_bad_lines="skip"
)

required_columns = {"subject", "body", "label"}
missing_columns = required_columns - set(df.columns)

if missing_columns:
    raise ValueError(f"Missing columns in CSV: {missing_columns}")

df["text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
df = df[["text", "label"]].dropna()

# Make sure labels are numeric: 0 = Not Phishing, 1 = Phishing
df["label"] = df["label"].astype(int)


# ------------------ TRAIN TEST SPLIT ------------------

train_texts, val_texts, train_labels, val_labels = train_test_split(
    df["text"].tolist(),
    df["label"].tolist(),
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)


# ------------------ TOKENIZATION ------------------

tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

train_encodings = tokenizer(
    train_texts,
    truncation=True,
    padding=True,
    max_length=256
)

val_encodings = tokenizer(
    val_texts,
    truncation=True,
    padding=True,
    max_length=256
)


# ------------------ DATASET CLASS ------------------

class SpamDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {
            key: torch.tensor(value[idx])
            for key, value in self.encodings.items()
        }

        item["labels"] = torch.tensor(self.labels[idx], dtype=torch.long)
        return item


train_dataset = SpamDataset(train_encodings, train_labels)
val_dataset = SpamDataset(val_encodings, val_labels)


# ------------------ CHECKPOINT LOGIC ------------------

latest_checkpoint = None

checkpoints = [
    d for d in os.listdir(CHECKPOINT_DIR)
    if d.startswith("checkpoint-")
]

if checkpoints:
    latest_checkpoint = os.path.join(
        CHECKPOINT_DIR,
        sorted(checkpoints, key=lambda x: int(x.split("-")[1]))[-1]
    )

    print("Resuming from checkpoint:", latest_checkpoint)


# ------------------ LOAD MODEL ------------------

model_path = latest_checkpoint if latest_checkpoint else "distilbert-base-uncased"

model = DistilBertForSequenceClassification.from_pretrained(
    model_path,
    num_labels=2
)


# ------------------ TRAINING ARGUMENTS ------------------

training_args = TrainingArguments(
    output_dir=CHECKPOINT_DIR,
    num_train_epochs=3,
    per_device_train_batch_size=4,
    per_device_eval_batch_size=8,
    logging_dir=LOG_DIR,
    logging_steps=100,
    save_steps=1000,
    save_total_limit=3,
    report_to="none"
)


# ------------------ TRAINER ------------------

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset
)


# ------------------ TRAIN ------------------

trainer.train(
    resume_from_checkpoint=latest_checkpoint if latest_checkpoint else None
)


# ------------------ FINAL SAVE ------------------

model.save_pretrained(CHECKPOINT_DIR)
tokenizer.save_pretrained(CHECKPOINT_DIR)

print("Training completed.")
print("Model saved at:", CHECKPOINT_DIR)