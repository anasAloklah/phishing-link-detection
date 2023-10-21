from http.server import HTTPServer, BaseHTTPRequestHandler
from FeaturesExtraction import Features,getDomain
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier

def readFile(fileName):
    src_data2 = open(fileName).read().strip().split('\n')
    return src_data2

whiteFile = readFile('top-1m.csv')
whiteList = []
n = len(whiteFile)
for i in range(0, n):
    whiteList.append(whiteFile[i].split(',')[1])
blackList = readFile('phishing-domains-new.txt')
src_data = 'datasetV2.csv'
df = pd.read_csv(src_data)

#print(df.shape)

df.drop('index', axis = 1, inplace = True)
#Splitting Data
X = df.drop('Result', axis = 1)
y = df['Result']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42)

rfc = RandomForestClassifier()
rfc = rfc.fit(X_train, y_train)
#model = MLPClassifier(alpha=0.01, hidden_layer_sizes=([100,100,100,]))

#model.fit(X_train, y_train)
print("init clasfifer ")
hostName = "localhost"
hostPort = 8000
class Serv(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/text')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET')
        self.end_headers()
        #self.wfile.write(bytes("ok", 'utf-8'))
        #path = self.path
        readDataState=self.path.find('readData')

        if readDataState != -1:
            path = self.path.replace('/?readData=', '')
            print(path)
            domain=getDomain(path)
            print(domain)

            if domain in whiteList:
                print("is safe in whiteList")
                self.wfile.write(bytes("is safe", 'utf-8'))
            elif domain in blackList :
                print("is suspicious in blacklist")

                self.wfile.write(bytes("is not safe", 'utf-8'))
            else:
                features = Features(path)
                featuresLis = features.getFeatures()
                print(featuresLis)
                y_pred=rfc.predict([featuresLis])
                #print(model.predict_proba([featuresLis]))
                print(y_pred)
                if(y_pred==1):
                    print("is safe")
                    self.wfile.write(bytes("is safe", 'utf-8'))
                else:
                    print("is suspicious")
                    self.wfile.write(bytes("is not safe", 'utf-8'))
                    f = open("phishing-domains.txt", "a+")
                    f.write("\n" + domain)
                    f.close()
                    blackList.append(domain)



httpd = HTTPServer((hostName, hostPort), Serv)
httpd.serve_forever()
