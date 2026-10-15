#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#ifndef _WIN32
#include <fcntl.h>
#endif
#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")
using socket_t = SOCKET;
static constexpr socket_t BAD_SOCKET = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t BAD_SOCKET = -1;
#endif
namespace py = pybind11;
namespace {
constexpr size_t MAGIC_N=8, EID_N=8, QUEUE_LIMIT=8, MAX_UNAUTH=65535, MAX_AUTH=33554431;
constexpr size_t UNAUTH_HEAD=2, AUTH_HEAD=5;
#ifdef _WIN32
struct SocketInit { SocketInit(){ WSADATA d{}; if(WSAStartup(MAKEWORD(2,2),&d)) throw std::runtime_error("WSAStartup failed"); } };
#else
struct SocketInit {};
#endif
void init_sockets(){ static SocketInit x; (void)x; }
void close_sock(socket_t s){ if(s==BAD_SOCKET)return; shutdown(s,
#ifdef _WIN32
SD_BOTH
#else
SHUT_RDWR
#endif
); 
#ifdef _WIN32
closesocket(s);
#else
close(s);
#endif
}
int sockerr(){
#ifdef _WIN32
return WSAGetLastError();
#else
return errno;
#endif
}
bool would_block(int e){
#ifdef _WIN32
return e==WSAEWOULDBLOCK || e==WSAEINTR;
#else
return e==EAGAIN || e==EWOULDBLOCK || e==EINTR;
#endif
}
void nonblocking(socket_t s){
#ifdef _WIN32
u_long mode=1; if(ioctlsocket(s,FIONBIO,&mode)!=0) throw std::runtime_error("ioctlsocket failed");
#else
int f=fcntl(s,F_GETFL,0); if(f<0 || fcntl(s,F_SETFL,f|O_NONBLOCK)<0) throw std::runtime_error("fcntl nonblocking failed");
#endif
}
void random_fill(uint8_t* p,size_t n){
#ifdef _WIN32
if(BCryptGenRandom(nullptr,p,(ULONG)n,BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) throw std::runtime_error("BCryptGenRandom failed");
#else
FILE* f=fopen("/dev/urandom","rb"); if(!f) throw std::runtime_error("cannot open /dev/urandom"); size_t got=fread(p,1,n,f); fclose(f); if(got!=n)throw std::runtime_error("random source failed");
#endif
}
std::string random_bytes(size_t n){std::string s(n,'\0');random_fill((uint8_t*)s.data(),n);return s;}
std::string as_string(const py::bytes& b){return (std::string)b;}
py::bytes as_bytes(const std::string& s){return py::bytes(s.data(),s.size());}
uint16_t u16(const uint8_t*p){return (uint16_t(p[0])<<8)|p[1];}
uint32_t u32(const uint8_t*p){return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];}
void put16(std::vector<uint8_t>&v,uint16_t x){v.push_back(x>>8);v.push_back(x&255);}
void put32(std::vector<uint8_t>&v,uint32_t x){v.push_back(x>>24);v.push_back((x>>16)&255);v.push_back((x>>8)&255);v.push_back(x&255);}
std::optional<size_t> find_bytes(const std::vector<uint8_t>& b,const std::string& m,size_t start=0){if(m.empty()||b.size()<m.size()||start>b.size()-m.size())return {};for(size_t i=start;i+m.size()<=b.size();++i)if(!memcmp(b.data()+i,m.data(),m.size()))return i;return {};}
void trim_prefix(std::vector<uint8_t>&b,const std::string&m){size_t keep=std::min(b.size(),m.size()-1);while(keep){if(!memcmp(b.data()+b.size()-keep,m.data(),keep)){b.erase(b.begin(),b.end()-static_cast<ptrdiff_t>(keep));return;}--keep;}b.clear();}
struct Message {std::string eid; std::string payload; bool authed=false;};
struct Pending {std::string payload; std::string eid; bool authed=false;};
struct Conn {
 socket_t sock=BAD_SOCKET; bool server_side=false; std::atomic<bool> authed{false}, closed{false}, backpressure{false}, handshake_started{false};
 std::string temp_cid, cid, magic1, magic2;
 std::mutex mutex; std::condition_variable cv; std::deque<Message> recvq; std::deque<Pending> sendq;
 std::vector<uint8_t> input, wire; size_t wire_off=0;
 std::mutex eid_mutex; std::set<std::string> eids;
};
class Pool {
public: explicit Pool(size_t n):n_(n){if(!n)throw std::invalid_argument("concurrency limit must be >= 1");}
 ~Pool(){stop();}
 void submit(std::function<void()> f){std::lock_guard<std::mutex>l(m_);if(stop_)return;q_.push_back(std::move(f));while(workers_.size()<n_)workers_.emplace_back([this]{run();});cv_.notify_one();}
 void stop(){{std::lock_guard<std::mutex>l(m_);stop_=true;q_.clear();}cv_.notify_all();for(auto&t:workers_)if(t.joinable()&&t.get_id()!=std::this_thread::get_id())t.join();workers_.clear();}
private:void run(){for(;;){std::function<void()>f;{std::unique_lock<std::mutex>l(m_);cv_.wait(l,[&]{return stop_||!q_.empty();});if(stop_&&q_.empty())return;f=std::move(q_.front());q_.pop_front();}try{f();}catch(const std::exception&e){std::cerr<<"[backing] callback error: "<<e.what()<<'\n';}catch(...){}}}
 size_t n_;std::mutex m_;std::condition_variable cv_;std::deque<std::function<void()>>q_;std::vector<std::thread>workers_;bool stop_=false;
};
std::vector<uint8_t> frame(const Conn&c,const Pending&p){std::vector<uint8_t>v;v.insert(v.end(),c.magic1.begin(),c.magic1.end());if(!p.authed){if(p.payload.size()>MAX_UNAUTH)throw std::length_error("handshake payload exceeds 65535 bytes");put16(v,(uint16_t)p.payload.size());}else{if(p.payload.size()>MAX_AUTH)throw std::length_error("payload exceeds 25-bit length limit");put32(v,(uint32_t)p.payload.size());v.push_back('0');v.insert(v.end(),p.eid.begin(),p.eid.end());}v.insert(v.end(),p.payload.begin(),p.payload.end());v.insert(v.end(),c.magic2.begin(),c.magic2.end());return v;}
// Parses complete frames while leaving any frame that cannot fit in the bounded receive queue in input.
template<class Deliver> bool parse(Conn&c,Deliver deliver){bool progress=false;for(;;){if(c.input.size()<MAGIC_N)return progress;auto p=find_bytes(c.input,c.magic1);if(!p){trim_prefix(c.input,c.magic1);return progress;}if(*p){c.input.erase(c.input.begin(),c.input.begin()+*p);progress=true;}bool a=c.authed.load();size_t hs=a?AUTH_HEAD+EID_N:UNAUTH_HEAD, body= MAGIC_N+hs;if(c.input.size()<body)return progress;uint32_t n= a?u32(c.input.data()+MAGIC_N):u16(c.input.data()+MAGIC_N);std::string eid;if(a){uint8_t flag=c.input[MAGIC_N+4];if(flag!='0'&&flag!='1'){c.input.erase(c.input.begin());progress=true;continue;}eid.assign((char*)c.input.data()+MAGIC_N+AUTH_HEAD,EID_N);}if(n>(a?MAX_AUTH:MAX_UNAUTH)){c.input.erase(c.input.begin());progress=true;continue;}size_t total=body+(size_t)n+MAGIC_N;auto p1=find_bytes(c.input,c.magic1,MAGIC_N);auto p2=find_bytes(c.input,c.magic2,body);if(p1&&*p1<total){c.input.erase(c.input.begin(),c.input.begin()+*p1);progress=true;continue;}if(p2&&*p2<total-MAGIC_N){c.input.erase(c.input.begin(),c.input.begin()+*p2+MAGIC_N);progress=true;continue;}if(c.input.size()<total)return progress;if(memcmp(c.input.data()+total-MAGIC_N,c.magic2.data(),MAGIC_N)){c.input.erase(c.input.begin());progress=true;continue;}std::string payload((char*)c.input.data()+body,n);if(!deliver(a,eid,std::move(payload)))return progress;c.input.erase(c.input.begin(),c.input.begin()+total);progress=true;}}
std::optional<double> timeout_arg(const py::object&o){if(o.is_none())return {};double x=py::cast<double>(o);if(x<0)throw py::value_error("timeout must be >= 0 or None");return x;}
std::optional<std::string> eid_arg(const py::object&o){if(o.is_none())return {};std::string e=as_string(py::cast<py::bytes>(o));if(e.size()!=EID_N)throw py::value_error("eid must be 8 bytes");return e;}
class Server {
public:
 Server(std::string h,uint16_t p,py::object hw,py::object oe,size_t sh,size_t se):host_(std::move(h)),port_(p),hw_(std::move(hw)),oe_(std::move(oe)),has_hw_(!hw_.is_none()),has_oe_(!oe_.is_none()),handshakes_(sh),exchanges_(se){init_sockets();magic1_=random_bytes(8);do{magic2_=random_bytes(8);}while(magic1_==magic2_);}
 ~Server(){stop();}
 void start(){if(running_)throw std::runtime_error("already running");addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;hints.ai_flags=AI_PASSIVE;addrinfo*r=nullptr;auto serv=std::to_string(port_);int rc=getaddrinfo(host_.empty()?nullptr:host_.c_str(),serv.c_str(),&hints,&r);if(rc)throw std::runtime_error("getaddrinfo failed");socket_t s=BAD_SOCKET;for(auto*x=r;x;x=x->ai_next){s=::socket(x->ai_family,x->ai_socktype,x->ai_protocol);if(s==BAD_SOCKET)continue;int yes=1;
#ifdef _WIN32
setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(const char*)&yes,sizeof(yes));
#else
setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
#endif
if(::bind(s,x->ai_addr,(int)x->ai_addrlen)==0&&::listen(s,SOMAXCONN)==0)break;close_sock(s);s=BAD_SOCKET;}freeaddrinfo(r);if(s==BAD_SOCKET)throw std::runtime_error("could not bind/listen");nonblocking(s);listener_=s;running_=true;io_=std::thread([this]{loop();});}
 void stop(){if(!running_.exchange(false)){handshakes_.stop();exchanges_.stop();return;}close_sock(listener_.exchange(BAD_SOCKET));if(io_.joinable()&&io_.get_id()!=std::this_thread::get_id())io_.join();{std::lock_guard<std::mutex>l(ids_m_);for(auto&x:temps_)close_conn(x.second);for(auto&x:ids_)close_conn(x.second);temps_.clear();ids_.clear();}handshakes_.stop();exchanges_.stop();}
 py::bytes MAGIC1()const{return as_bytes(magic1_);} py::bytes MAGIC2()const{return as_bytes(magic2_);}
 bool is_authed(py::bytes b){auto c=find(as_string(b));return c&&c->authed;}
 void set_backpressure(py::bytes b,bool v){auto c=find(as_string(b));if(!c)throw py::key_error("unknown cid");c->backpressure=v;}
 py::object send(py::bytes pb,py::bytes cb,py::object eb){auto c=find(as_string(cb));if(!c)throw py::key_error("unknown cid");if(!c->authed)throw std::runtime_error("normal send is unavailable before authentication; use send_handshake(temp_cid, data)");auto eid=eid_arg(eb);std::string e;if(eid)e=*eid;else{do{e=random_bytes(8);}while(!add_eid(c,e));}if(eid)add_eid(c,e);enqueue(c,Pending{as_string(pb),e,true});if(eid)return py::none();return py::object(as_bytes(e));}
 void send_handshake(py::bytes tb,py::bytes pb){auto c=find_temp(as_string(tb));if(!c)throw py::key_error("unknown temp_cid");if(c->authed)throw std::runtime_error("handshake send only allowed before auth");enqueue(c,Pending{as_string(pb),{},false});}
 py::object recv(py::bytes cb,py::object eb,py::object to){auto c=find(as_string(cb));if(!c)throw py::key_error("unknown cid");if(!c->authed)throw std::runtime_error("normal recv is unavailable before authentication; use recv_handshake(temp_cid)");auto e=eid_arg(eb);if(!e)throw py::value_error("eid is required for authenticated recv");return pop(c,e,true,timeout_arg(to));}
 py::object recv_handshake(py::bytes tb,py::object to){auto c=find_temp(as_string(tb));if(!c)throw py::key_error("unknown temp_cid");if(c->authed)throw std::runtime_error("handshake recv only allowed before auth");return pop(c,{},false,timeout_arg(to));}
 bool auth_finished(py::bytes tb,py::bytes nb,py::object confirm){std::string t=as_string(tb),n=as_string(nb);if(n.empty())throw py::value_error("new_cid must not be empty");auto c=find_temp(t);if(!c)throw py::key_error("unknown temp_cid");if(!confirm.is_none())enqueue(c,Pending{as_string(py::cast<py::bytes>(confirm)),{},false});{std::lock_guard<std::mutex>l(ids_m_);if(ids_.count(n))throw py::value_error("new_cid already in use");temps_.erase(t);c->cid=n;c->authed=true;ids_[n]=c;}return true;}
 void forget_exchange(py::bytes cb,py::bytes eb){auto c=find(as_string(cb));if(!c)throw py::key_error("unknown cid");auto e=as_string(eb);std::lock_guard<std::mutex>l(c->eid_mutex);c->eids.erase(e);std::lock_guard<std::mutex>q(c->mutex);auto&v=c->recvq;v.erase(std::remove_if(v.begin(),v.end(),[&](auto&m){return m.eid==e;}),v.end());}
private:
 std::shared_ptr<Conn> find(const std::string&id){std::lock_guard<std::mutex>l(ids_m_);auto i=ids_.find(id);return i==ids_.end()?nullptr:i->second;}std::shared_ptr<Conn> find_temp(const std::string&id){std::lock_guard<std::mutex>l(ids_m_);auto i=temps_.find(id);return i==temps_.end()?nullptr:i->second;}
 void enqueue(const std::shared_ptr<Conn>&c,Pending p){std::lock_guard<std::mutex>l(c->mutex);if(c->closed)throw std::runtime_error("connection closed");if(c->sendq.size()>=QUEUE_LIMIT)throw py::value_error("send queue full (maximum 8)");c->sendq.push_back(std::move(p));}
 bool add_eid(const std::shared_ptr<Conn>&c,const std::string&e){std::lock_guard<std::mutex>l(c->eid_mutex);return c->eids.insert(e).second;}
 py::object pop(const std::shared_ptr<Conn>&c,std::optional<std::string> e,bool a,std::optional<double> t){std::unique_lock<std::mutex>l(c->mutex);auto pred=[&]{return c->closed||std::any_of(c->recvq.begin(),c->recvq.end(),[&](auto&m){return m.authed==a&&(!a||m.eid==*e);});};bool ready=false;{py::gil_scoped_release release;if(t)ready=c->cv.wait_for(l,std::chrono::duration<double>(*t),pred);else{c->cv.wait(l,pred);ready=true;}}if(!ready)return py::none();auto i=std::find_if(c->recvq.begin(),c->recvq.end(),[&](auto&m){return m.authed==a&&(!a||m.eid==*e);});if(i==c->recvq.end())return py::none();std::string p=std::move(i->payload);c->recvq.erase(i);return as_bytes(p);}
 void close_conn(std::shared_ptr<Conn>&c){c->closed=true;close_sock(c->sock);c->sock=BAD_SOCKET;c->cv.notify_all();}
 void loop(){while(running_){socket_t ls=listener_;if(ls!=BAD_SOCKET){fd_set r;FD_ZERO(&r);FD_SET(ls,&r);timeval tv{0,2000};int n=select((int)(ls+1),&r,nullptr,nullptr,&tv);if(n>0&&FD_ISSET(ls,&r))for(;;){sockaddr_storage a{};
#ifdef _WIN32
int al=sizeof(a);
#else
socklen_t al=sizeof(a);
#endif
socket_t s=accept(ls,(sockaddr*)&a,&al);if(s==BAD_SOCKET)break;try{nonblocking(s);}catch(...){close_sock(s);continue;}auto c=std::make_shared<Conn>();c->sock=s;c->server_side=true;c->magic1=magic1_;c->magic2=magic2_;do{c->temp_cid=random_bytes(8);}while(find_temp(c->temp_cid));{std::lock_guard<std::mutex>l(ids_m_);temps_[c->temp_cid]=c;}Pending hello;hello.payload=magic1_+magic2_;hello.authed=false; // greeting is a raw 16-byte transport preface
c->wire.assign(hello.payload.begin(),hello.payload.end());c->wire_off=0;{std::lock_guard<std::mutex>l(conns_m_);conns_.push_back(c);}}
std::vector<std::shared_ptr<Conn>> all;{std::lock_guard<std::mutex>l(conns_m_);all=conns_;}for(auto&c:all)step(c);{std::lock_guard<std::mutex>l(conns_m_);conns_.erase(std::remove_if(conns_.begin(),conns_.end(),[](auto&c){return c->closed.load();}),conns_.end());}}
 }
 void step(const std::shared_ptr<Conn>&c){if(c->closed)return;socket_t s=c->sock;if(s==BAD_SOCKET)return;
 if(!c->input.empty()) parse(*c,[&](bool a,const std::string&e,std::string p){std::lock_guard<std::mutex>l(c->mutex);if(c->recvq.size()>=QUEUE_LIMIT)return false;c->recvq.push_back(Message{e,std::move(p),a});c->cv.notify_all();if(!a&&c->server_side&&!c->handshake_started.exchange(true)&&has_hw_){auto t=c->temp_cid;handshakes_.submit([this,t]{call_handshake(t);});}else if(a){bool fresh=add_eid(c,e);if(fresh&&has_oe_){std::string id=c->cid;exchanges_.submit([this,id,e]{call_exchange(id,e);});}}return true;});
 // Flush any partially written frame, then promote at most one queued item to wire output.
 if(c->wire_off>=c->wire.size()){c->wire.clear();c->wire_off=0;Pending p;bool have=false;{std::lock_guard<std::mutex>l(c->mutex);if(!c->sendq.empty()){p=std::move(c->sendq.front());c->sendq.pop_front();have=true;}}if(have){try{c->wire=frame(*c,p);}catch(...){c->closed=true;close_sock(s);c->sock=BAD_SOCKET;return;}}}
 if(!c->wire.empty()){int n=::send(s,(const char*)c->wire.data()+c->wire_off,(int)std::min<size_t>(c->wire.size()-c->wire_off,65536),
#ifdef _WIN32
0
#else
MSG_NOSIGNAL
#endif
);if(n>0)c->wire_off+=n;else if(n==0||!would_block(sockerr())){c->closed=true;close_sock(s);c->sock=BAD_SOCKET;c->cv.notify_all();return;}}
 bool room;{std::lock_guard<std::mutex>l(c->mutex);room=c->recvq.size()<QUEUE_LIMIT;}if(!c->backpressure&&room){uint8_t b[65536];int n=::recv(s,(char*)b,sizeof(b),0);if(n>0){c->input.insert(c->input.end(),b,b+n);parse(*c,[&](bool a,const std::string&e,std::string p){std::lock_guard<std::mutex>l(c->mutex);if(c->recvq.size()>=QUEUE_LIMIT)return false;c->recvq.push_back(Message{e,std::move(p),a});c->cv.notify_all();if(!a&&c->server_side&&!c->handshake_started.exchange(true)&&has_hw_){auto t=c->temp_cid;handshakes_.submit([this,t]{call_handshake(t);});}else if(a){bool fresh=add_eid(c,e);if(fresh&&has_oe_){std::string id=c->cid;exchanges_.submit([this,id,e]{call_exchange(id,e);});}}return true;});}else if(n==0||!would_block(sockerr())){c->closed=true;close_sock(s);c->sock=BAD_SOCKET;c->cv.notify_all();}}
 }
 void call_handshake(std::string t){py::gil_scoped_acquire g;try{hw_(as_bytes(t));}catch(py::error_already_set&e){std::cerr<<"handshake_worker: "<<e.what()<<'\n';}}
 void call_exchange(std::string c,std::string e){py::gil_scoped_acquire g;try{oe_(as_bytes(c),as_bytes(e));}catch(py::error_already_set&x){std::cerr<<"on_exchange: "<<x.what()<<'\n';}}
 std::string host_;uint16_t port_;std::string magic1_,magic2_;py::object hw_,oe_;bool has_hw_,has_oe_;Pool handshakes_,exchanges_;std::atomic<bool>running_{false};std::atomic<socket_t>listener_{BAD_SOCKET};std::thread io_;std::mutex ids_m_,conns_m_;std::map<std::string,std::shared_ptr<Conn>>ids_,temps_;std::vector<std::shared_ptr<Conn>>conns_;
};
class Client {
public:
 Client(std::string h,uint16_t p,py::object oe,size_t se):host_(std::move(h)),port_(p),oe_(std::move(oe)),has_oe_(!oe_.is_none()),exchanges_(se){init_sockets();}
 ~Client(){disconnect();}
 void connect(){if(connected_)throw std::runtime_error("already connected");addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;addrinfo*r=nullptr;auto serv=std::to_string(port_);if(getaddrinfo(host_.c_str(),serv.c_str(),&hints,&r))throw std::runtime_error("getaddrinfo failed");socket_t s=BAD_SOCKET;for(auto*x=r;x;x=x->ai_next){s=::socket(x->ai_family,x->ai_socktype,x->ai_protocol);if(s==BAD_SOCKET)continue;if(::connect(s,x->ai_addr,(int)x->ai_addrlen)==0)break;close_sock(s);s=BAD_SOCKET;}freeaddrinfo(r);if(s==BAD_SOCKET)throw std::runtime_error("connect failed");std::array<char,16>g{};size_t got=0;while(got<g.size()){
#ifdef _WIN32
int n=::recv(s,g.data()+got,(int)(g.size()-got),0);
#else
ssize_t n=::recv(s,g.data()+got,g.size()-got,0);
#endif
if(n<=0){close_sock(s);throw std::runtime_error("failed to receive framing greeting");}got+=n;}conn_=std::make_shared<Conn>();conn_->sock=s;conn_->magic1.assign(g.data(),8);conn_->magic2.assign(g.data()+8,8);magic1_=conn_->magic1;magic2_=conn_->magic2;nonblocking(s);connected_=true;io_=std::thread([this]{loop();});}
 void disconnect(){if(!connected_.exchange(false)){exchanges_.stop();return;}if(conn_){conn_->closed=true;close_sock(conn_->sock);conn_->sock=BAD_SOCKET;conn_->cv.notify_all();}if(io_.joinable()&&io_.get_id()!=std::this_thread::get_id())io_.join();exchanges_.stop();}
 py::object send(py::bytes pb,py::object eb){auto c=conn_;if(!c||!connected_)throw std::runtime_error("not connected");if(!c->authed)throw std::runtime_error("normal send is unavailable before authentication; use send_handshake(data)");auto e=eid_arg(eb);std::string id;if(e)id=*e;else{do{id=random_bytes(8);}while(!add_eid(id));}if(e)add_eid(id);enqueue(Pending{as_string(pb),id,true});if(e)return py::none();return py::object(as_bytes(id));}
 void send_handshake(py::bytes pb){auto c=conn_;if(!c||!connected_||c->authed)throw std::runtime_error("handshake send only allowed while connected and unauthenticated");enqueue(Pending{as_string(pb),{},false});}
 py::object recv(py::object eo,py::object to){auto c=conn_;if(!c||!c->authed)throw std::runtime_error("normal recv is unavailable before authentication; use recv_handshake()");auto e=eid_arg(eo);if(!e)throw py::value_error("eid is required for authenticated recv");return pop(e,true,timeout_arg(to));}
 py::object recv_handshake(py::object to){auto c=conn_;if(!c||c->authed)throw std::runtime_error("handshake recv only allowed before authentication");return pop({},false,timeout_arg(to));}
 bool auth_finished(py::bytes b){if(!conn_||!connected_)throw std::runtime_error("not connected");std::string id=as_string(b);if(id.empty())throw py::value_error("cid must not be empty");conn_->cid=id;conn_->authed=true;return true;}
 bool is_authed()const{return conn_&&conn_->authed;}py::bytes cid()const{return conn_&&conn_->authed?as_bytes(conn_->cid):py::bytes();}py::bytes MAGIC1()const{return as_bytes(magic1_);}py::bytes MAGIC2()const{return as_bytes(magic2_);}
 void set_backpressure(bool b){if(!conn_)throw std::runtime_error("not connected");conn_->backpressure=b;}
 void forget_exchange(py::bytes eb){if(!conn_)return;auto e=as_string(eb);std::lock_guard<std::mutex>l(conn_->eid_mutex);conn_->eids.erase(e);std::lock_guard<std::mutex>q(conn_->mutex);auto&v=conn_->recvq;v.erase(std::remove_if(v.begin(),v.end(),[&](auto&m){return m.eid==e;}),v.end());}
private:
 bool add_eid(const std::string&e){std::lock_guard<std::mutex>l(conn_->eid_mutex);return conn_->eids.insert(e).second;}
 void enqueue(Pending p){std::lock_guard<std::mutex>l(conn_->mutex);if(conn_->sendq.size()>=QUEUE_LIMIT)throw py::value_error("send queue full (maximum 8)");conn_->sendq.push_back(std::move(p));}
 py::object pop(std::optional<std::string> e,bool a,std::optional<double> t){auto c=conn_;std::unique_lock<std::mutex>l(c->mutex);auto pred=[&]{return c->closed||std::any_of(c->recvq.begin(),c->recvq.end(),[&](auto&m){return m.authed==a&&(!a||m.eid==*e);});};bool ready=false;{py::gil_scoped_release release;if(t)ready=c->cv.wait_for(l,std::chrono::duration<double>(*t),pred);else{c->cv.wait(l,pred);ready=true;}}if(!ready)return py::none();auto i=std::find_if(c->recvq.begin(),c->recvq.end(),[&](auto&m){return m.authed==a&&(!a||m.eid==*e);});if(i==c->recvq.end())return py::none();auto p=std::move(i->payload);c->recvq.erase(i);return as_bytes(p);}
 void loop(){while(connected_&&conn_&&!conn_->closed){auto c=conn_;socket_t s=c->sock;if(s==BAD_SOCKET)break;if(!c->input.empty()) parse(*c,[&](bool a,const std::string&e,std::string p){std::lock_guard<std::mutex>l(c->mutex);if(c->recvq.size()>=QUEUE_LIMIT)return false;c->recvq.push_back(Message{e,std::move(p),a});c->cv.notify_all();if(a){bool fresh=add_eid(e);if(fresh&&has_oe_){auto id=c->cid;exchanges_.submit([this,id,e]{call_exchange(id,e);});}}return true;});if(c->wire_off>=c->wire.size()){c->wire.clear();c->wire_off=0;Pending p;bool have=false;{std::lock_guard<std::mutex>l(c->mutex);if(!c->sendq.empty()){p=std::move(c->sendq.front());c->sendq.pop_front();have=true;}}if(have){try{c->wire=frame(*c,p);}catch(...){c->closed=true;break;}}}if(!c->wire.empty()){int n=::send(s,(const char*)c->wire.data()+c->wire_off,(int)std::min<size_t>(c->wire.size()-c->wire_off,65536),
#ifdef _WIN32
0
#else
MSG_NOSIGNAL
#endif
);if(n>0)c->wire_off+=n;else if(n==0||!would_block(sockerr())){c->closed=true;break;}}
bool room;{std::lock_guard<std::mutex>l(c->mutex);room=c->recvq.size()<QUEUE_LIMIT;}if(!c->backpressure&&room){uint8_t b[65536];int n=::recv(s,(char*)b,sizeof(b),0);if(n>0){c->input.insert(c->input.end(),b,b+n);parse(*c,[&](bool a,const std::string&e,std::string p){std::lock_guard<std::mutex>l(c->mutex);if(c->recvq.size()>=QUEUE_LIMIT)return false;c->recvq.push_back(Message{e,std::move(p),a});c->cv.notify_all();if(a){bool fresh=add_eid(e);if(fresh&&has_oe_){auto id=c->cid;exchanges_.submit([this,id,e]{call_exchange(id,e);});}}return true;});}else if(n==0||!would_block(sockerr())){c->closed=true;break;}}std::this_thread::sleep_for(std::chrono::milliseconds(1));}if(conn_){conn_->closed=true;conn_->cv.notify_all();}}
 void call_exchange(std::string id,std::string e){py::gil_scoped_acquire g;try{oe_(as_bytes(id),as_bytes(e));}catch(py::error_already_set&x){std::cerr<<"on_exchange: "<<x.what()<<'\n';}}
 std::string host_;uint16_t port_;py::object oe_;bool has_oe_;Pool exchanges_;std::shared_ptr<Conn>conn_;std::string magic1_,magic2_;std::atomic<bool>connected_{false};std::thread io_;
};
}
PYBIND11_MODULE(backing,m){m.doc()="Networking v2.0 queued TCP backend";m.attr("MAX_UNAUTH_PAYLOAD")=MAX_UNAUTH;m.attr("MAX_AUTH_PAYLOAD")=MAX_AUTH;m.attr("QUEUE_LIMIT")=QUEUE_LIMIT;
py::class_<Server>(m,"Server").def(py::init<std::string,uint16_t,py::object,py::object,size_t,size_t>(),py::arg("host"),py::arg("port"),py::arg("handshake_worker")=py::none(),py::arg("on_exchange")=py::none(),py::arg("simult_handshakes")=4,py::arg("simult_exchanges")=4)
.def("start",&Server::start).def("stop",[](Server&s){py::gil_scoped_release g;s.stop();})
.def("send",[](Server&s,py::bytes data,py::bytes cid,py::object eid){return s.send(data,cid,eid);},py::arg("data"),py::arg("cid"),py::arg("eid")=py::none())
.def("send_handshake",&Server::send_handshake,py::arg("temp_cid"),py::arg("data"))
.def("recv",[](Server&s,py::bytes cid,py::object eid,py::object timeout){return s.recv(cid,eid,timeout);},py::arg("cid"),py::arg("eid"),py::arg("timeout")=py::none())
.def("recv_handshake",[](Server&s,py::bytes cid,py::object timeout){return s.recv_handshake(cid,timeout);},py::arg("temp_cid"),py::arg("timeout")=py::none())
.def("auth_finished",&Server::auth_finished,py::arg("temp_cid"),py::arg("new_cid"),py::arg("confirmation_payload")=py::none()).def("is_authed",&Server::is_authed).def("set_backpressure",&Server::set_backpressure).def("forget_exchange",&Server::forget_exchange).def_property_readonly("MAGIC1",&Server::MAGIC1).def_property_readonly("MAGIC2",&Server::MAGIC2);
py::class_<Client>(m,"Client").def(py::init<std::string,uint16_t,py::object,size_t>(),py::arg("host"),py::arg("port"),py::arg("on_exchange")=py::none(),py::arg("simult_exchanges")=4)
.def("connect",[](Client&c){py::gil_scoped_release g;c.connect();}).def("disconnect",[](Client&c){py::gil_scoped_release g;c.disconnect();})
.def("send",[](Client&c,py::bytes data,py::object eid){return c.send(data,eid);},py::arg("data"),py::arg("eid")=py::none()).def("send_handshake",&Client::send_handshake)
.def("recv",[](Client&c,py::object eid,py::object timeout){return c.recv(eid,timeout);},py::arg("eid"),py::arg("timeout")=py::none()).def("recv_handshake",[](Client&c,py::object timeout){return c.recv_handshake(timeout);},py::arg("timeout")=py::none())
.def("auth_finished",&Client::auth_finished).def_property_readonly("is_authed",&Client::is_authed).def_property_readonly("cid",&Client::cid).def_property_readonly("MAGIC1",&Client::MAGIC1).def_property_readonly("MAGIC2",&Client::MAGIC2).def("set_backpressure",&Client::set_backpressure).def("forget_exchange",&Client::forget_exchange);
}
