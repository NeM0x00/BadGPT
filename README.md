# BadGPT  

BadGPT is a powerful and versatile framework designed to streamline the bug bounty process. It offers tools for reconnaissance, scanning, searching, and exploitation across various targets such as domains, IPs, JavaScript files, CVEs, secrets, URLs, parameters, endpoints, credentials, and more. **BadGPT** is your all-in-one solution for starting bug bounty hunting with ease.  

---

## ✨ Features  
- **Reconnaissance:** Subdomain discovery, endpoint enumeration, and domain analysis.  
- **Scanning:** IP scanning, port enumeration, and vulnerability detection.  
- **Search & Exploit:** Extract sensitive data like secrets, credentials, and CVEs.  
- **Output Management:** Categorized outputs for targeted analysis.  

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

<h1 align="center">
  <img src="https://i.imgur.com/ZEGGucH.png" alt="arsenal" width="700" >
  <br>
</h1>


<h3 align="left">Support:</h3>  
<p><a href="https://www.buymeacoffee.com/nemoxoo"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="Micro0x00" /></a></p><br><br>  


