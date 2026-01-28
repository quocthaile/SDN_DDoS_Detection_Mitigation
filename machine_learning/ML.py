import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from datetime import datetime

class MachineLearning:
    def __init__(self):
        # Resolve paths relative to the project root (portable across machines)
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(self.script_dir)
        self.models_dir = os.path.join(self.project_root, 'models')
        self.plots_dir = os.path.join(self.script_dir, 'plots')
        
        # Ensure output folders exist (models + plots)
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.plots_dir, exist_ok=True)
        
        print("Loading dataset ...")
        
        # 1. Load dataset.csv containing flow features and labels
        try:
            dataset_path = os.path.join(self.project_root, 'dataset', 'dataset.csv')
            self.flow_dataset = pd.read_csv(dataset_path)
            print(f"-> Loaded '{dataset_path}'")
        except FileNotFoundError:
            print(f"ERROR: File '{dataset_path}' not found!")
            return

        # 2. Data cleaning: remove NaN/Inf values that break training
        print("Cleaning Infinity/NaN values ...")
        self.flow_dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
        self.flow_dataset.dropna(inplace=True)

        # 3. Feature selection from dataset.csv
        # These columns represent flow-level statistics used to detect DDoS:
        # - ip_proto: IP protocol number (e.g., TCP/UDP/ICMP).
        # - icmp_code, icmp_type: ICMP-specific fields (useful for ICMP floods).
        # - flow_duration_sec, flow_duration_nsec: flow lifetime length.
        # - idle_timeout, hard_timeout: flow timeouts from the SDN controller.
        # - flags: TCP flags summary (indicates scan/flood patterns).
        # - packet_count, byte_count: total packets/bytes in the flow.
        # - packet_count_per_second, packet_count_per_nsecond: packet rate.
        # - byte_count_per_second, byte_count_per_nsecond: byte rate.
        self.feature_cols = [
            'ip_proto', 'icmp_code', 'icmp_type', 
            'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout', 'hard_timeout', 'flags', 
            'packet_count', 'byte_count', 
            'packet_count_per_second', 'packet_count_per_nsecond', 
            'byte_count_per_second', 'byte_count_per_nsecond'
        ]
        
        # Keep only columns that exist in the current dataset.csv
        existing_cols = [c for c in self.feature_cols if c in self.flow_dataset.columns]
        # The target label is the class (e.g., benign vs attack)
        if 'label' not in self.flow_dataset.columns:
            print("ERROR: Label column not found!")
            return

        # Build feature matrix X and target vector y
        self.X = self.flow_dataset[existing_cols].values.astype('float64')
        self.y = self.flow_dataset['label'].values

        print(f"\n[FEATURE INFO]")
        print(f"Dataset shape: {self.flow_dataset.shape}")
        print(f"Total features requested: {len(self.feature_cols)}")
        print(f"Features actually used: {len(existing_cols)}")
        print(f"Feature list: {existing_cols}")
        
        # Show statistics for each feature
        print(f"\nFeature Statistics (before scaling):")
        for col in existing_cols:
            print(f"  {col:25s}: min={self.flow_dataset[col].min():.4f} max={self.flow_dataset[col].max():.4f} mean={self.flow_dataset[col].mean():.4f}")
        
        print(f"X shape: {self.X.shape}\n")

        # 4. Scaling: standardize features for fair model comparison
        print("Scaling data ...")
        self.scaler = StandardScaler()
        self.X = self.scaler.fit_transform(self.X)
        
        print(f"Scaler mean: {self.scaler.mean_}")
        print(f"Scaler scale (std): {self.scaler.scale_}\n")

        # 5. Train/test split to evaluate generalization
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            self.X, self.y, test_size=0.25, random_state=42
        )
        
        # Store metrics for later plotting
        self.results = {}

    def train_and_evaluate(self):
        # Define candidate ML models for comparison
        models = {
            "Logistic Regression": LogisticRegression(solver='liblinear', random_state=0),
            "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5, metric='minkowski', p=2),
            "Naive Bayes": GaussianNB(),
            "Decision Tree": DecisionTreeClassifier(criterion='entropy', random_state=0),
            # Random Forest training parameters:
            # - n_estimators=20: number of decision trees in the forest.
            # - criterion='entropy': split quality metric (information gain).
            # - random_state=0: fixed seed for reproducibility.
            "Random Forest": RandomForestClassifier(n_estimators=20, criterion='entropy', random_state=0)
        }

        print("\n" + "="*50)
        print("STARTING MODEL COMPARISON")
        print("="*50)

        for name, model in models.items():
            # Measure training + inference time per model
            start_time = datetime.now()
            print(f"\nTraining {name} ...")
            
            # Train
            model.fit(self.X_train, self.y_train)
            
            # Predict
            y_pred = model.predict(self.X_test)
            
            # Evaluate performance with accuracy and confusion matrix
            acc = accuracy_score(self.y_test, y_pred)
            cm = confusion_matrix(self.y_test, y_pred)
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            print(f"-> Accuracy: {acc*100:.2f}%")
            print(f"-> Time: {duration}")
            print("-> Confusion Matrix:")
            print(cm)
            
            # Store results for plotting (CM structure: [[TN, FP], [FN, TP]])
            self.results[name] = {
                'accuracy': acc,
                'cm': cm.flatten() # [TN, FP, FN, TP]
            }

            # Save the Random Forest model and scaler for later inference
            if name == "Random Forest":
                print(f"\n[SAVING] Exporting {name} model and scaler...")
                rf_model_path = os.path.join(self.models_dir, 'rf_model.pkl')
                scaler_path = os.path.join(self.models_dir, 'scaler.pkl')
                joblib.dump(model, rf_model_path)
                joblib.dump(self.scaler, scaler_path)
                print(f"-> Model saved to '{rf_model_path}'")
                print(f"-> Scaler saved to '{scaler_path}'")

    def plot_comparison(self):
        # Plot accuracy comparison and aggregated confusion-matrix metrics
        print("\nGenerating Comparison Plots (English) ...")
        
        # Prepare data for plotting
        model_names = list(self.results.keys())
        
        # 1. Accuracy bar chart
        accuracies = [self.results[m]['accuracy'] * 100 for m in model_names]
        
        plt.figure(figsize=(12, 7))
        bars = plt.bar(model_names, accuracies, color=['#3498db', '#e74c3c', '#2ecc71', '#f1c40f', '#9b59b6'])
        
        plt.title('Algorithm Accuracy Comparison', fontsize=16, pad=20)
        plt.xlabel('Algorithms', fontsize=12)
        plt.ylabel('Accuracy (%)', fontsize=12)
        plt.ylim(0, 100)
        
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                     f'{height:.2f}%', ha='center', va='bottom', fontsize=11)
        
        plt.xticks(rotation=15, ha='right')
        plt.tight_layout()
        plt.subplots_adjust(bottom=0.15)
        accuracy_plot_path = os.path.join(self.plots_dir, 'accuracy_comparison.png')
        plt.savefig(accuracy_plot_path, dpi=150, bbox_inches='tight')
        print(f"-> Saved '{accuracy_plot_path}'")
        plt.show()
        plt.close()

        # 2. Confusion-matrix metrics (TN, FP, FN, TP) per model
        
        labels = ['TN (True Neg)', 'FP (False Pos)', 'FN (False Neg)', 'TP (True Pos)']
        x = np.arange(len(labels))  # label locations
        width = 0.15  # width of the bars
        
        fig, ax = plt.subplots(figsize=(12, 7))
        
        # Define colors for models
        colors = ['#FF5733', '#33FF57', '#3357FF', '#F3FF33', '#000000']
        
        for i, model_name in enumerate(model_names):
            # cm_values = [TN, FP, FN, TP]
            cm_values = self.results[model_name]['cm']
            offset = width * i
            rects = ax.bar(x + offset, cm_values, width, label=model_name, color=colors[i])

        # Add some text for labels, title and custom x-axis tick labels, etc.
        ax.set_ylabel('Number of Samples')
        ax.set_title('Confusion Matrix Metrics by Algorithm')
        ax.set_xticks(x + width * 2)
        ax.set_xticklabels(labels)
        ax.legend()

        plt.tight_layout()
        plt.subplots_adjust(bottom=0.12)
        cm_comparison_path = os.path.join(self.plots_dir, 'confusion_matrix_comparison.png')
        plt.savefig(cm_comparison_path, dpi=150, bbox_inches='tight')
        print(f"-> Saved '{cm_comparison_path}'")
        plt.show()
        plt.close()

    def plot_individual_confusion_matrices(self):
        """Plot individual confusion matrix heatmaps for each model"""
        print("\nGenerating Individual Confusion Matrix Heatmaps ...")
        
        # Re-train models to get full confusion matrices per algorithm
        models = {
            "Logistic Regression": LogisticRegression(solver='liblinear', random_state=0),
            "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5, metric='minkowski', p=2),
            "Naive Bayes": GaussianNB(),
            "Decision Tree": DecisionTreeClassifier(criterion='entropy', random_state=0),
            "Random Forest": RandomForestClassifier(n_estimators=20, criterion='entropy', random_state=0)
        }
        
        fig, axes = plt.subplots(2, 3, figsize=(16, 10))
        axes = axes.flatten()
        
        for idx, (name, model) in enumerate(models.items()):
            model.fit(self.X_train, self.y_train)
            y_pred = model.predict(self.X_test)
            cm = confusion_matrix(self.y_test, y_pred)
            
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[idx], 
                       cbar=False, square=True, annot_kws={'size': 12})
            axes[idx].set_title(f'{name}', fontsize=13, fontweight='bold', pad=10)
            axes[idx].set_xlabel('Predicted', fontsize=11)
            axes[idx].set_ylabel('Actual', fontsize=11)
        
        # Hide the extra subplot
        axes[5].axis('off')
        
        plt.suptitle('Confusion Matrix Heatmaps by Algorithm', fontsize=16, fontweight='bold', y=0.98)
        plt.tight_layout(rect=[0, 0, 1, 0.96])
        heatmaps_path = os.path.join(self.plots_dir, 'confusion_matrix_heatmaps.png')
        plt.savefig(heatmaps_path, dpi=150, bbox_inches='tight')
        print(f"-> Saved '{heatmaps_path}'")
        plt.show()
        plt.close()

def main():
    # End-to-end training + evaluation + visualization
    ml = MachineLearning()
    # Only proceed if data loaded successfully
    if hasattr(ml, 'X'):
        ml.train_and_evaluate()
        ml.plot_comparison()
        ml.plot_individual_confusion_matrices()
        print("\nDone! All models trained, evaluated, RF exported, and plots generated.")

if __name__ == "__main__":
    main()