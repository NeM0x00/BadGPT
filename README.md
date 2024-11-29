# BadGPT  

**BadGPT** is a robust framework designed to simplify and optimize the bug bounty process. Equipped with a suite of tools for reconnaissance, scanning, and exploitation, BadGPT helps researchers efficiently identify and exploit vulnerabilities. Whether you're hunting subdomains, analyzing JavaScript files, detecting secrets, or testing endpoints, **BadGPT** serves as your all-in-one solution for streamlined penetration testing.

---

## ✨ Features  

### 1. Reconnaissance
- Subdomain enumeration with **Subfinder**.
- Endpoint discovery using **gau** (Get All URLs) and **Katana**.
- Comprehensive JavaScript file analysis via **getJS**.

### 2. Scanning
- IP and port scanning with **Naabu**.
- HTTP endpoint testing and interaction with **httpx**.

### 3. Data Extraction
- Detect secrets, credentials, and CVEs from the collected data.
- Extract URLs and endpoints efficiently for further testing.

### 4. Output Management
- Categorized outputs (JSON/Text) for targeted analysis.
- Detailed logging with **logify** and **gologger**.

### 5. Notifications
- **Discord notifications** to track scanning and exploitation progress in real-time.

---

```
BBBBBBBBBBBBBBBBB                                d::::::d       GGGGGGGGGGGGGPPPPPPPPPPPPPPPPP   TTTTTTTTTTTTTTTTTTTTTTT
B::::::::::::::::B                               d::::::d    GGG::::::::::::GP::::::::::::::::P  T:::::::::::::::::::::T
B::::::BBBBBB:::::B                              d::::::d  GG:::::::::::::::GP::::::PPPPPP:::::P T:::::::::::::::::::::T
BB:::::B     B:::::B                             d:::::d  G:::::GGGGGGGG::::GPP:::::P     P:::::PT:::::TT:::::::TT:::::T
  B::::B     B:::::B  aaaaaaaaaaaaa      ddddddddd:::::d G:::::G       GGGGGG  P::::P     P:::::PTTTTTT  T:::::T  TTTTTT
  B::::B     B:::::B  a::::::::::::a   dd::::::::::::::dG:::::G                P::::P     P:::::P        T:::::T        
  B::::BBBBBB:::::B   aaaaaaaaa:::::a d::::::::::::::::dG:::::G                P::::PPPPPP:::::P         T:::::T        
  B:::::::::::::BB             a::::ad:::::::ddddd:::::dG:::::G    GGGGGGGGGG  P:::::::::::::PP          T:::::T        
  B::::BBBBBB:::::B     aaaaaaa:::::ad::::::d    d:::::dG:::::G    G::::::::G  P::::PPPPPPPPP            T:::::T        
  B::::B     B:::::B  aa::::::::::::ad:::::d     d:::::dG:::::G    GGGGG::::G  P::::P                    T:::::T        
  B::::B     B:::::B a::::aaaa::::::ad:::::d     d:::::dG:::::G        G::::G  P::::P                    T:::::T        
  B::::B     B:::::Ba::::a    a:::::ad:::::d     d:::::d G:::::G       G::::G  P::::P                    T:::::T        
BB:::::BBBBBB::::::Ba::::a    a:::::ad::::::ddddd::::::dd G:::::GGGGGGGG::::GPP::::::PP                TT:::::::TT      
B:::::::::::::::::B a:::::aaaa::::::a d:::::::::::::::::d  GG:::::::::::::::GP::::::::P                T:::::::::T      
B::::::::::::::::B   a::::::::::aa:::a d:::::::::ddd::::d    GGG::::::GGG:::GP::::::::P                T:::::::::T      
BBBBBBBBBBBBBBBBB     aaaaaaaaaa  aaaa  ddddddddd   ddddd       GGGGGG   GGGGPPPPPPPPPP                TTTTTTTTTTT 


                                                                                     By Youssef Elsheikh
```
## 📦 Requirements  

### Tools  
Ensure the following tools are installed:  
```
Katana
Subfinder
Gau
Naabu
Nuclei # (pending implementation)
```

🚀 Installation
Clone the repository:

```
git clone https://github.com/NeM0x00/BadGPT.git
cd BadGPT
```
Create a domains file containing your target domains:
```
example.com
testsite.org
othersite.net
```
Run the framework:
```
go run main.go
```
Optionally, compile the framework into an executable:

```
go build -o output_folder/badgpt
./output_folder/badgpt
```
# To-Do List

## 🚀 Features to Implement
- [ ] Implement reusme function
- [ ] Add Logo in the entry
- [ ] Scanner(nulcei)
- [ ] 403 Bypass
- [ ] Use Templates for exposure
- [ ] Fuzzing (subdomains-endpoints)
- [ ] Process percentage


## 🐞 Bugs to Fix
- [ ] Track your Process and enable debugging 

## 🛠️ Improvements
- [ ] Optimize database querie
- [ ] Work on result (Json&PDF)
- [ ] Add unit tests for API endpoints

💡 Contribution
We welcome contributions! Feel free to fork the repository, submit a pull request, or report issues.

<h3 align="left">Support:</h3>  
only for Egyptian here is instapay  "nem0x00@instapay"
<p><a href="https://ipn.eg/S/nem0x00/instapay/1PjuHv"> <img align="left" src="https://traidmod.net/wp-content/uploads/2024/06/InstaPay-Logo-240x240.webp" height="140" width="150" alt="NeM0x00" /></a></p><br><br>  
<p><a href="https://www.buymeacoffee.com/nemoxoo"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="NeM0x00" /></a></p><br><br>  


