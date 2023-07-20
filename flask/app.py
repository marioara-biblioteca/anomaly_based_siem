from flask import *
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

import base64
from io import BytesIO

from server_utils import *
# from connect import *

app = Flask(__name__)

conn_type='file'
bro_df,features=create_df_conn(conn_log_file)  if 'conn' == conn_type else create_df_file(file_log_file) if 'file' == conn_type else create_df_http(http_log_file) 
bro_matrix=to_matrix.fit_transform(bro_df[features],normalize=True)   
scores=detect_optimal_number_of_clusters(bro_matrix)

import webbrowser
visibility = ''
@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if request.form.get('getHints') == "Get Hints":
            return redirect(url_for('hints'))
        elif  request.form.get('train') == 'Train':
            return render_template('index.html',visibility='visible')
            
        elif  request.form.get('retrain') == 'Retrin':
            print("Retrain")
        elif  request.form.get('compare') == 'Compare':
            print("Compare")
        elif  request.form.get('showClusters') == 'Show Clusters':
            print("Show Clusters")
        elif  request.form.get('save') == 'Save':
            print("Save")
    elif request.method == 'GET':
        return render_template('index.html')
    
    return render_template("index.html",visibility='hidden')

@app.route('/hints')
def hints():
    fig, ax = plt.subplots(figsize = (6,4))
    pd.DataFrame({'Num Clusters':range(2,10), 'score':scores}).plot(ax=ax,x='Num Clusters', y='score')
    plt.title("Initial Data Clusters")
    output=BytesIO()
    FigureCanvas(fig).print_png(output)
    return Response(output.getvalue(), mimetype='image/png')