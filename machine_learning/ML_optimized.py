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
from sklearn.model_selection import GridSearchCV

class MachineLearning:
    def __init__(self):
        # Get the script's directory and create paths relative to project root
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(self.script_dir)
        self.models_dir = os.path.join(self.project_root, 'models')
        self.plots_dir = os.path.join(self.script_dir, 'plots')
        
        # Create necessary directories
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.plots_dir, exist_ok=True)
        
        print("Loading dataset ...")
        
        # 1. Load Data
        try:
            dataset_path = os.path.join(self.project_root, 'dataset', 'dataset.csv')
            self.flow_dataset = pd.read_csv(dataset_path)
            print(f"-> Loaded '{dataset_path}'")
        except FileNotFoundError:
            print(f"ERROR: File '{dataset_path}' not found!")
            return

        # 2. Data Cleaning
        print("Cleaning Infinity/NaN values ...")
        self.flow_dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
        self.flow_dataset.dropna(inplace=True)

        # 3. Feature Selection (Giữ lại các cột quan trọng từ ML_v2)
        self.feature_cols = [
            'ip_proto', 'icmp_code', 'icmp_type', 
            'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout', 'hard_timeout', 'flags', 
            'packet_count', 'byte_count', 
            'packet_count_per_second', 'packet_count_per_nsecond', 
            'byte_count_per_second', 'byte_count_per_nsecond'
        ]
        
        # Kiểm tra xem các cột có tồn tại không
        existing_cols = [c for c in self.feature_cols if c in self.flow_dataset.columns]
        if 'label' not in self.flow_dataset.columns:
            print("ERROR: Label column not found!")
            return

        self.X = self.flow_dataset[existing_cols].values.astype('float64')
        self.y = self.flow_dataset['label'].values

        # 4. Scaling
        print("Scaling data ...")
        self.scaler = StandardScaler()
        self.X = self.scaler.fit_transform(self.X)

        # 5. Split Data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            self.X, self.y, test_size=0.25, random_state=42
        )
        
        # Dictionary to store results for plotting
        self.results = {}

    def train_and_evaluate(self):
        models = {
            "Logistic Regression": LogisticRegression(solver='liblinear', random_state=0),
            "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5, metric='minkowski', p=2),
            "Naive Bayes": GaussianNB(),
            "Decision Tree": DecisionTreeClassifier(criterion='entropy', random_state=0),
            # "Random Forest": RandomForestClassifier(n_estimators=20, criterion='entropy', random_state=0)
            'Random Forest': RandomForestClassifier(
                n_estimators=200,       # Tăng lên 200 cây để ổn định hơn (Mặc định là 100)
                max_depth=20,           # Giới hạn độ sâu để tránh model quá nặng, giảm độ trễ dự đoán
                min_samples_split=5,    # Giảm nhiễu (Noise), tránh học quá chi tiết từng gói tin lạ
                min_samples_leaf=2,     # Giúp model tổng quát hóa tốt hơn
                n_jobs=-1,              # Sử dụng đa luồng CPU để dự đoán nhanh hơn
                random_state=42,
                class_weight='balanced' # CỰC KỲ QUAN TRỌNG: Tự động cân bằng nếu dữ liệu tấn công ít hơn dữ liệu thường
            )
        }

        print("\n" + "="*50)
        print("STARTING MODEL COMPARISON")
        print("="*50)

        for name, model in models.items():
            start_time = datetime.now()
            print(f"\nTraining {name} ...")
            
            # Train
            model.fit(self.X_train, self.y_train)
            
            # Predict
            y_pred = model.predict(self.X_test)
            
            # Evaluate
            acc = accuracy_score(self.y_test, y_pred)
            cm = confusion_matrix(self.y_test, y_pred)
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            print(f"-> Accuracy: {acc*100:.2f}%")
            print(f"-> Time: {duration}")
            print("-> Confusion Matrix:")
            print(cm)
            
            # Store results for plotting
            # CM structure: [[TN, FP], [FN, TP]]
            self.results[name] = {
                'accuracy': acc,
                'cm': cm.flatten() # [TN, FP, FN, TP]
            }

            # SAVE RANDOM FOREST MODEL SPECIALLY
            if name == "Random Forest":
                print(f"\n[SAVING] Exporting {name} model and scaler...")
                rf_model_path = os.path.join(self.models_dir, 'rf_model.pkl')
                scaler_path = os.path.join(self.models_dir, 'scaler.pkl')
                joblib.dump(model, rf_model_path)
                joblib.dump(self.scaler, scaler_path)
                print(f"-> Model saved to '{rf_model_path}'")
                print(f"-> Scaler saved to '{scaler_path}'")

    def plot_comparison(self):
        print("\nGenerating Comparison Plots (English) ...")
        
        # Prepare data for plotting
        model_names = list(self.results.keys())
        
        # 1. ACCURACY PLOT
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

        # 2. CONFUSION MATRIX METRICS PLOT (Replicating ML.py style)
        # We will plot TN, FP, FN, TP groups for each model
        
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
        
        # Re-train models to get full confusion matrices
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
    def optimize_random_forest(self):
        """
        Run GridSearch to find the best Random Forest parameters.
        """
        print("Searching for optimal parameters (GridSearch)... This may take a few minutes.")
        
        # 1. Define the parameter search space
        param_grid = {
            'n_estimators': [100, 200],        # Number of trees (more = better, but slower)
            'max_depth': [10, 20, None],       # Max depth (controls overfitting)
            'min_samples_split': [2, 5, 10],   # Min samples to split a node
            'min_samples_leaf': [1, 2, 4],     # Min samples at a leaf node
            'bootstrap': [True, False]         # Sampling method
        }

        # 2. Initialize base model
        rf = RandomForestClassifier(random_state=42)

        # 3. Configure Grid Search
        # cv=3: 3-fold cross validation
        # n_jobs=-1: Use all CPU cores
        # verbose=2: Show detailed progress
        grid_search = GridSearchCV(estimator=rf, param_grid=param_grid, 
                                   cv=3, n_jobs=-1, verbose=2, scoring='accuracy')

        # 4. Run training
        grid_search.fit(self.X_train, self.y_train)

        # 5. Report best result
        print(f"Best parameters found: {grid_search.best_params_}")
        print(f"Best accuracy: {grid_search.best_score_:.4f}")

        # 6. Save best model
        best_rf = grid_search.best_estimator_
        
        # Save model
        rf_path = os.path.join(self.models_dir, 'rf_model_optimized.pkl')
        joblib.dump(best_rf, rf_path)
        print(f"-> Saved optimized model to: {rf_path}")
        
        # Save scaler (must match the model)
        scaler_path = os.path.join(self.models_dir, 'scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
        print(f"-> Saved scaler to: {scaler_path}")
        
        return best_rf

def main():
    ml = MachineLearning()
    if hasattr(ml, 'X'): # Only proceed if data loaded successfully
        ml.train_and_evaluate()
        ml.plot_comparison()
        ml.plot_individual_confusion_matrices()
        print("\nDone! All models trained, evaluated, RF exported, and plots generated.")
        # Try to optimize model
        # best_model = ml.optimize_random_forest()

if __name__ == "__main__":
    main()