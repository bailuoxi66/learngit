//用于压力测试：
{
	58.87.64.16
	bUGJjUhXx29t4aS
	/data/code/Tars/cpp/stress
}


/common/query?account=1514361731118_10001_U443&ip=172.16.33.166&pubkey=2i8Y23142NcZgk9X8SK3PoA9PeOOED9QVq4RQFBXWPU&question=12&sessionId=10001_1514361731118_10001_U443_1514361731&transeq=57031&sign=f46e06cd5576d706119f55f3240a1c6d

注意一下：
common/query?account
ip
pubkey
question
sessionId
transeq

http://szcport.wezhuiyi.com/common/query?pubkey=fngndXw%2FUw0yb8uFyJp6Jaq0ZnCijZcKbg4LfS7deKE&question=11111&sign=8c0af33a18006ab7657324d36fe25708&ip=demo.kfyy.wezhuiyi.com&sessionId=71360004
http://demo.kfyy.wezhuiyi.com:90/common/query?pubkey=fngndXw%2FUw0yb8uFyJp6Jaq0ZnCijZcKbg4LfS7deKE&question=11111&sign=8c0af33a18006ab7657324d36fe25708&ip=demo.kfyy.wezhuiyi.com&sessionId=71360004
/*
{
	查看发行：
	cat /proc/version    而/proc/version的结果主要由/proc/sys/kernel/ostype,/proc/sys/kernel/osrelease和/proc/sys/kernel/version这3个文件汇聚而成:
	gcc -v
	uname -r/-a
	cat *|wc -l
	free
	top
	strace -p 3324       追踪进程
	写入的速度：time dd if=/dev/zero of=/tmp/test.dat bs=1G count=1
	# hdparm -Tt /dev/sda
	/dev/sda:
    Timing cached reads: 6676 MB in 2.00 seconds = 3340.18 MB/sec             2秒钟读取了6676MB的缓存,约合3340.18 MB/sec
    Timing buffered disk reads: 218 MB in 3.11 seconds = 70.11 MB/sec         在3.11秒中读取了218MB磁盘(物理读),读取速度约合70.11 MB/sec
	ldd test  (ldd不是个可执行程序，而只是个shell脚本)
		
}
*/



curl "http://10.71.22.75:8000/common/query?account=1514361731118_10001_U443&ip=172.16.33.166&pubkey=2i8Y23142NcZgk9X8SK3PoA9PeOOED9QVq4RQFBXWPU&question=12&sessionId=10001_1514361731118_10001_U443_1514361731&transeq=57031&sign=f46e06cd5576d706119f55f3240a1c6d"

一定要注意：每个字符的大小写，防止引起的签名错误
cid（坐席辅助必填字段，访问渠道）
http://10.3.1.11:150/yibot/query?&account=18703609115&cid=access_cid&ip=127.0.0.1&labels=WeiXin&question=%E5%AE%A2%E8%88%B1%E8%A1%8C%E6%9D%8E%E9%81%97%E7%95%99%E6%9F%A5%E6%89%BE&sessionId=sd&l5_debug=1Hgs4u3vM7zg&categoryId=6&sign=19b1b6c2a2d3361de89f62035f43112d

//需要urldecode的，因为pubkey和question发送的时候需要urlencode
/*
			if (tmpv[0] == "question" || tmpv[0]=="pubkey" || tmpv[0]=="userQuestion" || tmpv[0]=="labels" || tmpv[0]=="faq" || tmpv[0]=="route_info")
			{
				m_params[tmpv[0]] = urldecode(tmpv[1]);
			}
*/

请求的key转换
/*

	string HttpTimerInfo::ConvertKey (const string &key)
	{
		string ret = key;
		if (m_cvtMap.size() < 1)
		{
			//init convert map
			m_cvtMap["openId"] = "account";
			m_cvtMap["channel"] = "labels";
			m_cvtMap["user_id"] = "account";
			m_cvtMap["session_id"] = "sessionId";
			m_cvtMap["user_ip"] = "ip";
			
		}
		map<string, string>::iterator it = m_cvtMap.find(key);
		if (it != m_cvtMap.end())
		{
			ret = it->second;
		}
		return ret;
	}
*/

//                                       	五大酷刑
										ERRNO_PARSE_PARAM_ERROR
										ERRNO_GET_PARAM_NULL

//  请求参数属性
{
										pubkey      必填，需要urlencode
										question    必填，需要urlencode
										cid
										eid
										sign        必填，签名
										ip          必填，提问者IP，这部分是yibot系统中很多关键功能的依赖
										account     必填，提问者唯一标识（手机）
										sessionId   必填，会话Id，注意大小写
										labels
}

//去哪儿，分期乐，卷皮
qunar.kf.wezhuiyi.com/match/query?sessionId=111&userId=111&userMessage=%E9%94%99%E8%BF%87%E9%A3%9E%E6%9C%BA%E8%B5%B7%E9%A3%9E&msgId=111&bizType=hotel&corp=qunar&option=null
fql.kf.wezhuiyi.com/common/query?account=1515317410961_10041_U245&ip=117.136.15.130&pubkey=JIE36eTtQQ47L9yKefvC7rm%2BNOo8%2BmpjyTM9MynL1tg&question=%E4%B8%BA%E4%BB%80%E4%B9%88%E6%88%91%E6%B2%A1%E6%9C%89%E8%B5%84%E6%A0%BC%E5%8F%96%E7%8E%B0%EF%BC%9F%EF%BC%9F&sessionId=10041_1515317410961_10041_U245_1515317412&source=yiconnect&transeq=969949&sign=0e7ebc95fe4b4ab5a7a56d86586ee7f3
juanpi.kf.wezhuiyi.com/query?account=188066274&cid=0&ip=221.198.132.186&pubkey=YbeqFY2zJZBGheU8deF9nj%2FhOS4HDquhw1vqa%2BfE%2Bz4&question=%E4%BD%A0%E5%A5%BD+%E6%88%91%E6%8A%8A%E8%A1%A3%E6%9C%8D%E5%AF%84%E5%9B%9E%E5%93%AA%E9%87%8C&sessionId=230703323&sign=fc031ed93923627449b2006d5bf69cf0

{
	http://qunar.kf.wezhuiyi.com/match/query
	http://qunar.kf.wezhuiyi.com/guess/query
	http://qunar.kf.wezhuiyi.com/healthcheck
}
计算签名的原始串：

//私钥是如何获取的，獲取m_pid, m_bid
{
		m_aeskey = "ca72ed29dc5eed56b203057f50c6c4de";
		biz_priv = GetBizFromPubkey (pubkey, this);
					{
						    string iv("00000000000000000000000000000000");
							string biz_str("");
							if (pubkey.empty() /*|| 56 != pubkey.size()*/)
							{
								return "";
							}
							Aes256 aes_en (hti->m_aeskey, iv); 

							string bizkey_hex = base64_decode (pubkey);
							aes_en.Decode (bizkey_hex, &biz_str);
							
							return biz_str;
					}
		vector<string> bizkeys;
		MySplitTag((char*)biz_priv.c_str(), (char*)"|", bizkeys);
		biz_id = atoi(bizkeys[0].c_str());
		m_pid = (biz_id >> 16);
		m_bid = biz_id & 0x0000FFFF;
}

CMCDProc::run(../etc/adaptor_mcd.conf)
	{
	->  Init(../etc/adaptor_mcd.conf)
		->  LoadCfg(../etc/adaptor_mcd.conf)
			->  loadConfig()
			{
			        _log_para.log_level_    = log_level    = 0
					_log_para.log_type_     = log_type     = 1
					_log_para.path_         = path         = "../log/"
					_log_para.name_prefix_  = name_prefix  = "adaptor_stat"
					_log_para.max_file_size_= max_file_size= 10000000
					_log_para.max_file_no_  = max_file_no  = 2
					
					_stat_log_para.log_level_    = log_level  = 1
					_stat_log_para.log_type_     = log_type   = 2
					_stat_log_para.path_         = path       = "../log/"
					_stat_log_para.name_prefix_  = name_prefix = "adatpor_stat"
					_stat_log_para.max_file_size_= 10000000
					_stat_log_para.max_file_no_  = 2
					_stat_log_para.gap           = stat_gap = 60                              //不知道有什么用?
					_stat_log_para.time_out_1    = time_out_1 = 100                           //不知道有什么用?
					_stat_log_para.time_out_2    = time_out_1 = 500
					_stat_log_para.time_out_3    = time_out_1 = 1000
					
					_healthCheckOn = 1
					
					_water_log.path_       = path = "../log/"
					_water_log.name_prefix = name_prefix = "adaptor_water"
					
					_feedback_log.path        = path = "../log/"
					_feedback_log.name_prefix_= name_prefix = "feedback_water"
					
					_parse_path = "../bin/parse_biz.so"
					
					_force_rbu_ip   = ""
					_force_rbu_port = 0
					
					m_param_parser_so = ""
					
					_force_so_pid = 0
					_force_so_bid = 0
					_force_so_path = "../bin/bizso/biz_beibei_smartbox.so"
					_force_no_license = 1
					_license_file = "../bin/license.dat"
					
					_time_out = search_time_out = 5000
					_max_question_len = max_question_len = 1000
			}
			
			->  LoadConfCache
			{
					m_conf_cache_size = cache_size = 10
					m_conf_shmkey = shmkey = 10150200
					m_node_num = node_num = 10000
					m_block_size = block_size = 100
					m_read_only  = read_only  = 0
			}
					
	    ->  InitBuffer()
		{
			m_recv_bug = new char[BUFF_SIZE]         #define BUFF_SIZE 20 * 1024 * 1024
			m_send_buf = new char[BUFF_SIZE]
		}
					
		->  InitLog()
			->  DEBUG_OPEN
				{
					stat file:../log/adaptor_log.1
					dest_file not exist:../log/adaptor.log.1
					cur_file_no:1
				}
			->  CWaterLog::Instance()->Init(log_para->path_, log_para->name_prefix_, log_para->max_file_size_, log_para->max_file_no_)
			    ->  open
					{
						stat file:../log/adaptor_water.20171228.log.1
						dest_file not exist:../log/adaptor_water.20171228.log.1
						cur_file_no:1
					}
			->  CFeedbackLog::Instance()->Init(log_para->path_, log_para->name_prefix_, log_para->max_file_size_, log_para->max_file_no_);
				->  open
					{
						stat file:../log/feedback_water.20171228.log.1
						dest_file not exist:../log/feedback_water.20171228.log.1
						cur_file_no:1
					}
		->  InitStat()
			->  Inittialize((char*)stat_file.c_str(), stat_para->max_file_size_, stat_para->max_file_no_, m_cfg._stat_timeout_1, m_cfg._stat_timeout_2, m_cfg._stat_timeout_3)
			    ->  ClearStat()        m_bUseMutex:0    //m_bUseMutex,m_iLastClearTime,m_iTypeNum,m_astTypeInfo
					{
						if(m_bUseMutex)
							pthread_mutex_lock(&m_stMutex)
						m_iLastClearTime = time(0)
						m_iTypeNum = 0
						memset(m_astTypeInfo, 0, sizeof(m_astTypeInfo))
						if(m_bUseMutex)
							pthread_mutex_unlock(&m_stMutex)
					}
		->  InitIpc()
			{
				    m_mq_ccd_2_mcd = _mqs["mq_ccd_2_mcd"];
					m_mq_mcd_2_ccd = _mqs["mq_mcd_2_ccd"];
					m_mq_dcc_2_mcd = _mqs["mq_dcc_2_mcd"];
					m_mq_mcd_2_dcc = _mqs["mq_mcd_2_dcc"];

					m_mq_inner_ccd_2_mcd = _mqs["mq_ccd_2_mcd_inner"];
					m_mq_mcd_2_inner_ccd = _mqs["mq_mcd_inner_2_ccd"];

					assert(m_mq_ccd_2_mcd != NULL);
					assert(m_mq_mcd_2_ccd != NULL);
					assert(m_mq_dcc_2_mcd != NULL);
					assert(m_mq_mcd_2_dcc != NULL);
					assert(m_mq_inner_ccd_2_mcd != NULL);
					assert(m_mq_mcd_2_inner_ccd != NULL);

					if (add_mq_2_epoll(m_mq_ccd_2_mcd, disp_ccd, this))
					{
						LogErrPrint("Add input mq to EPOLL fail!");
						err_exit();
					}

					if (add_mq_2_epoll(m_mq_dcc_2_mcd, disp_dcc, this))
					{
						LogErrPrint("Add mq_dcc_2_mcd to EPOLL fail!");
						err_exit();
					}

					if (add_mq_2_epoll(m_mq_inner_ccd_2_mcd, disp_inner_ccd, this))
					{
						LogErrPrint("Add mq_inner_ccd_2_mcd to EPOLL fail!");
						err_exit();
					}
			}
		->  InitTemplate()   HTTP_HEAD_MAX = 5120
			{
				组装http头部,这里有个两个：http_head, http_json_head
				/*
				HTTP/1.1                
				Server: MCP-Simple-HTTP
				Content-Length:                                 
				Cache-Control: no-cache
				Content-Type: text/html; charset=utf-8
				Connection: Keep-Alive
				Access-Control-Allow-Origin: *
				*/
			}
			->  m_http_template.Init(http_head, head_len, args, 3) || m_http_json_template.Init(http_json_head, json_head_len, args, 3);               //这里需要查看下额外的源码
		->  InitSo()                   SMARTBOX_PID:0, SMARTBOX_BID:16
			->  DynamicSoMgr::Instance()->UnLoadSo(SMARTBOX_PID, SMARTBOX_BID)       //_map_biz_func_name_ptr  
			->  GetFuncList(funclist)  //vector<string> funclist
				{	
						vec.clear();
					//	vec.push_back(FUNC_AES_KEY);
						vec.push_back(FUNC_INIT_REQUEST);
						vec.push_back(FUNC_BEFORE_SMU);
						vec.push_back(FUNC_AFTER_SMU);
						vec.push_back(FUNC_BUILD_RESP);
						vec.push_back(FUNC_INIT);
				}
			->  DynamicSoMgr::Instance()->LoadSo("../bin/bizso/biz_smartbox.so", SMARTBOX_PID, SMARTBOX_BID, funclist, true)            // _map_path_bizso
			  //DynamicSoMgr::LoadSo(const string& path, uint32_t pid, uint32_t bid, const vector<string>& func_list, bool flag_global)            pid=1049,flag_global = false;
				->  ToBiz(pid, bid)               // _map_path_bizso
				->  new_so_bizid(path, bizid, fun_list,flag_global)                           
					->  sf->open(path.c_str(), flag_global)
						{
							if (flag_global)
							{
								_handle = dlopen(so_file, RTLD_LAZY | RTLD_GLOBAL);
							}
							else
							{
								_handle = dlopen(so_file, RTLD_NOW);
							}
						}
					->  get_func(func_list[i].c_str)  
						{
							_map_biz_func_name_ptr[bizid][func_list[i]] = ptr
						}
						_map_path_bizso[path].map_bizs[bizid] = 0;
						_map_path_bizso[path].so_handle = sf;
						_map_biz_sopath[bizid] = path;  
			->  DynamicSoMgr::Instance()->GetFunc(SMARTBOX_PID, SMARTBOX_BID, FUNC_INIT);
				{
						uint64_t bizid = ToBiz(pid, bid);
						LOG_DEBUG("GetFunc...278...bizid:%d", bizid);
						map<uint64_t, MAP_FUNC_NAME_PTR>::iterator bit = _map_biz_func_name_ptr.find(bizid);
						if (bit==_map_biz_func_name_ptr.end())
						{
							return NULL;
						}
						MAP_FUNC_NAME_PTR::iterator mit = bit->second.find(func_name);
						if (mit == bit->second.end())
						{
							return NULL;
						}
						return mit->second;
				}
		->  LogMark("%s", m_cfg.ToString().c_str());
			{
				
				-----------------config begin-------------------
				log_level:0
				max_question_len:1000
				timeout:5000
				-----------------config end---------------------
				/*
				string CAdaptorCfgMng::ToString()
				{
					string ret = "\n-----------------config begin-------------------\n";	
					char buf[64];

					memset(buf, 0, sizeof(buf));
					snprintf(buf, sizeof(buf), "log_level:%d\n", _log_para.log_level_);
					ret += string(buf);

					memset(buf, 0, sizeof(buf));
					snprintf(buf, sizeof(buf), "max_question_len:%u\n", _max_question_len);
					ret += string(buf);

					memset(buf, 0, sizeof(buf));
					snprintf(buf, sizeof(buf), "timeout:%u\n", _time_out);
					ret += string(buf);
					
					ret += "-----------------config end---------------------\n";
					return ret;
				}
				*/
			}
		->  CBusinessConfig::Instance()->Init(m_cfg.m_conf_cache_size, m_cfg.m_conf_shmkey, m_cfg.m_node_num, m_cfg.m_block_size, m_cfg.m_read_only)
		->  LoadHost2BizMap("../etc/host_conf.json");                        //加载白名单
			{
				struct SHostConf
				{
					int m_biz;
					set<string> m_white_list;
				};
				//示例
				/*
					[
						{
							"host": "10.3.1.11:120",
							"biz":132973547,
							"white_list":["10.3.1.11"]
						}
					]
				*/
				//load Host2biz map from config file
				int HttpTimerInfo::LoadHost2bizMap (const char * file_path)
				{
					LogDebug("LoadHost2bizMap...923");
					ifstream fin (file_path);
					if (!fin.is_open())
					{
						DEBUG_P (LOG_ERROR, "[LoadHost2bizMap] Open host to biz map file. file_name:[%s] \n", file_path);
						return -1;
					}

					Json::Reader reader;
					Json::Value  root;
					if (!reader.parse(fin, root, false))
					{
						DEBUG_P (LOG_ERROR, "[LoadHost2bizMap] parse host to biz map file with json failed. file_name:[%s] \n", file_path);
						return -1;
					}

					m_hostConf.clear();
					int size = root.size();
					LogDebug("root.size()  :%d", size);
					for (int i = 0; i < size; ++i)
					{
						Json::Value item = root[i];
						string host("");
						SHostConf host_conf;
						if (item["host"].isNull() || (!item["host"].isString()))
						{
							DEBUG_P (LOG_ERROR, "[LoadHost2bizMap] get host from json failed!. host:[%s] \n", item["host"].asString().c_str());
							continue;
						}
						host =  item["host"].asString();
						LogDebug("host:%s", host.c_str());
						if (item["biz"].isNull() || (!item["biz"].isInt()))
						{
							DEBUG_P (LOG_ERROR, "[LoadHost2bizMap] get biz from json failed!. biz:[%s] \n", item["biz"].asString().c_str());
							continue;
						}
						host_conf.m_biz = item["biz"].asInt();
						if (item["white_list"].isNull() || (!item["white_list"].isArray()))
						{
							DEBUG_P (LOG_ERROR, "[LoadHost2bizMap] get white list from json failed!.  \n");
							continue;
						}
						int ip_size = item["white_list"].size();
						for (int k = 0; k < ip_size; ++k)
						{
							string white_li("");
							white_li = item["white_list"][k].asString();
							LogDebug("white_li:%s", white_li.c_str);
							host_conf.m_white_list.insert (item["white_list"][k].asString());
						}
						m_hostConf[host] = host_conf;
					}
					return 0;
				}
			}
		->  LoadFuncParse(m_cfg._parse_path);                                _parse_path:../bin/parse_biz.so
			{
				//parse_biz.cpp
					//get_default(hti->m_params, "categoryId", "0");
					string get_default(MapParam& mparams, const string& key, const string& def_val)
					{
						MapParam::iterator it = mparams.find(key);
						if (it != mparams.end())
						{
							return it->second;
						}
						return def_val;
					}
					int parse_biz(HttpTimerInfo* hti, const string& pubkey)
					{
						if(pubkey=="ndGzYWkEcEw1eUzqdCzwimuNJIziKCKY8rbQyeWGtqT5ucLUUEig2RQY")        //這裏是滴滴
						{
							hti->m_aeskey = "WvKvCpBDPPCUHe0IqNELBak0hnw5kWqR";
							string categoryId = get_default(hti->m_params, "categoryId", "0");
							int cid = atoi(categoryId.c_str());
							hti->m_pid = 1005; 
							if (cid==38)
							{
								// client
								hti->m_bid = 1002;
							}
							else if(cid==4024)
							{
								// drive phone
								hti->m_bid = 1003;
							}
							else if(cid==24222)
							{
								// zhuanche driver
								hti->m_bid = 1023;
							}
							else if(cid==24226)
							{
								// zhuanche passenger
								hti->m_bid= 1024;
							}
							else if(cid==32256)
							{
								// kuaiche driver
								hti->m_bid = 1025;
							}
							else if(cid==32258)
							{
								// kuaiche passenger
								hti->m_bid = 1026;
							}
							else
							{
								// 6 is driver, other also send to driver
								hti->m_bid = 1001;
							}
							return 0;
						}
						else if(hti->m_params.find("corp") != hti->m_params.end()
								&& hti->m_params.find("bizType") != hti->m_params.end())              //這裏是去哪兒（corp, bizType）
						{
							hti->m_pid = 2077;
							if("hotel" == hti->m_params["bizType"])
							{
								hti->m_bid = 1001;
							}
							else if("flight" ==  hti->m_params["bizType"])
							{
								hti->m_bid = 1002;
							}
							return 0;
						}
						else if(hti->m_params.find("bizType") != hti->m_params.end())                //這裏是携程(bizType)
						{
							hti->m_pid = 1049;
							string bizType = hti->m_params["bizType"];
							string tag = hti->m_params["tag"];
							
							if (bizType == "hotel")
							{
								hti->m_bid = 1001;
							}
							else if(bizType == "flight" &&  tag.find("national") != string::npos)
							{
								hti->m_bid = 1003;
							}
							else if(bizType == "flight" &&  tag.find("international") != string::npos)
							{
								hti->m_bid = 1004;
							}
							else if(bizType == "car")
							{
								hti->m_bid = 1005;
							}
							return 0;
						}
						else
						{
							return -1;
						}
					}
				//LoadFuncParse
				{
					static void* pHandle = NULL;

					try
					{
						if(pHandle)
						{
							dlclose(pHandle);
						}
						pHandle = dlopen(file_path.c_str(), RTLD_NOW);
					}
					catch(...)
					{
						LogDebug("load function parse failed");
						m_funcParse = NULL;
						return -1;
					}
					if(pHandle == NULL)
					{
						LogError("open so file failed, path:%s", file_path.c_str());
						m_funcParse = NULL;
						return -1;
					}
					char* pErrMsg = dlerror();
					if(pErrMsg != NULL)
					{
						LogError("%s", pErrMsg);
						m_funcParse = NULL;
						return -1;
					}
					m_funcParse = (FUNCPARSE)dlsym(pHandle, "parse_biz");
					pErrMsg = dlerror();
					if(pErrMsg != NULL)
					{
						LogError("%s", pErrMsg);
						m_funcParse = NULL;
						dlclose(pHandle);
						return -1;
					}
					LogMark("Load Parse biz function success.");
					return 0;
				}
			}
		->	signal(SIGUSR1, sigusr1_handle)
		->  signal(SIGUSR2, sigusr2_handle)                                  //這裏不懂
			{
				static void sigusr2_handle(int sig_val)
				{
				  yibot::adaptor::obj_checkflag.set_flag(yibot::adaptor::FLG_CTRL_STOP);
				  signal(SIGUSR2, sigusr2_handle);
				}

				static void sigusr1_handle(int sig_val)
				{
				  yibot::adaptor::obj_checkflag.set_flag(yibot::adaptor::FLG_CTRL_RELOAD);
				  signal(SIGUSR1, sigusr1_handle);
				}
			}
	}
		//Init  
	{
		add_mq_2_epoll(m_mq_ccd_2_mcd, disp_ccd, this);
		add_mq_2_epoll(m_mq_dcc_2_mcd, disp_dcc, this);
		add_mq_2_epoll(m_mq_inner_ccd_2_mcd, disp_inner_ccd, this);
		{
			DispatchCCD()
			{
				{
					int32_t ret = 0;
					int32_t deal_count = 0;
					unsigned data_len = 0;

					unsigned long long flow = 0;

					TCCDHeader* ccdheader = (TCCDHeader*)m_recv_buf;
					timeval ccd_time;
					while (deal_count < 1000)
					{
						data_len = 0;
						ret = m_mq_ccd_2_mcd->try_dequeue(m_recv_buf, BUFF_SIZE, data_len, flow);

						if (ret || data_len < CCD_HEADER_LEN)
						{
							++deal_count;
							continue;
						}

						uint32_t client_ip 	= ccdheader->_ip;
						ccd_time.tv_sec 	= ccdheader->_timestamp;
						ccd_time.tv_usec 	= ccdheader->_timestamp_msec * 1000;

						if (ccd_rsp_data != ccdheader->_type)
						{
							DEBUG_P(LOG_ERROR, "[DispatchCcd] ccdheader->_type invalid "
									"expect: %d actual: %d client_ip: %s\n",
									ccd_rsp_data, ccdheader->_type, INET_ntoa(client_ip).c_str());
							++deal_count;
							continue;
						}

						HandleRequest(m_recv_buf + CCD_HEADER_LEN,
											data_len - CCD_HEADER_LEN,
											flow,
											client_ip,
											ccd_time);

						++deal_count;
					}
				}
			}
			DispatchInnerCCD()
			{
				{
					int32_t ret = 0;
					int32_t deal_count = 0;
					unsigned data_len = 0;

					unsigned long long flow = 0;

					TCCDHeader* ccdheader = (TCCDHeader*)m_recv_buf;
					timeval ccd_time;
					while (deal_count < 1000)
					{
						data_len = 0;
						ret = m_mq_inner_ccd_2_mcd->try_dequeue(m_recv_buf, BUFF_SIZE, data_len, flow);

						if (ret || data_len < CCD_HEADER_LEN)
						{
							++deal_count;
							continue;
						}

						uint32_t client_ip 	= ccdheader->_ip;
						ccd_time.tv_sec 	= ccdheader->_timestamp;
						ccd_time.tv_usec 	= ccdheader->_timestamp_msec * 1000;

						if (ccd_rsp_data != ccdheader->_type)
						{
							DEBUG_P(LOG_ERROR, "[DispatchInnerCCD] ccdheader->_type invalid "
									"expect: %d actual: %d client_ip: %s\n",
									ccd_rsp_data, ccdheader->_type, INET_ntoa(client_ip).c_str());

							++deal_count;
							continue;
						}

						HandleInnerRequest(m_recv_buf + CCD_HEADER_LEN,
											data_len - CCD_HEADER_LEN,
											flow,
											client_ip,
											ccd_time);

						++deal_count;
					}
				}
			    //HandleInnerRequest
				{
					{
						DEBUG_P(LOG_ERROR, "Inner message.\n");
						uint16_t service_type;
						char* out_buf = NULL;
						uint32_t out_buf_len = 0;
						uint32_t msg_seq = 0;

						LongconnUtils::Instance()->unpack_longconn_packet((const char*)data, data_len,
								&msg_seq, service_type, (unsigned char**)&out_buf, &out_buf_len);

						switch(service_type)
						{
							case SERVICE_PING:
								Echo_ping ((char *)out_buf, out_buf_len, msg_seq, flow);
								break;
							case SERVICE_PUSH_CONFIG:
								Update_config ((const char *)out_buf, out_buf_len, msg_seq, flow);
								break;
							default:
								DEBUG_P(LOG_ERROR, "[CMCDProc] UNKNOW HandleInnerRequest search_no=%u service_type=%u down_ip %s\n",
										msg_seq, service_type, INET_ntoa(client_ip).c_str());
								break;
						}
						return 0;
					}
				}
				//这里终于输出了Inner message....
				->  LongconnUtils::Instance()->unpack_longconn_packet((const char*)data, data_len,&msg_seq, service_type, (unsigned char**)&out_buf, &out_buf_len);
					{
						switch(service_type)
						{
							case SERVICE_PING:
								Echo_ping ((char *)out_buf, out_buf_len, msg_seq, flow);
								break;
							case SERVICE_PUSH_CONFIG:
								Update_config ((const char *)out_buf, out_buf_len, msg_seq, flow);
								break;
							default:
								DEBUG_P(LOG_ERROR, "[CMCDProc] UNKNOW HandleInnerRequest search_no=%u service_type=%u down_ip %s\n",
										msg_seq, service_type, INET_ntoa(client_ip).c_str());
								break;
						}
					}
					//Update_config...herehere...
			}
			DispatchCCD();
		}
	}
	
	
	
	
	
	
	
	
	
	{
		[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitIpc:334] InitIpc...325
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitIpc:343] allready...Ipc...334
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitIpc:351] InitIpc...assert...345
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitIpc:369] add...InitIpc...363
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitTemplate:377] InitTemplate...371
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitTemplate:397] HTTP_HEAD_MAX:5120  ARG_CNT_MAX:32
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitTemplate:398] data:  json_data:0^M^_?^A  head:(null)  head_len:0  json_head_len:0
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitTemplate:428] json_data:
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitTemplate:429] data:
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitSo:212] InitSo...pid:0  bid:0
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitSo:243] SMARTBOX_PID:0  SMARTBOX_BID:16
[2018-01-18 04:05:40] UnLoadSo, pid:0, bid:16, bizid:16
[2018-01-18 04:05:40] bizid:16
[2018-01-18 04:05:40] NewSo path:../bin/bizso/biz_smartbox.so, bizid:16, so func:BeforeSmu
[2018-01-18 04:05:40] NewSo path:../bin/bizso/biz_smartbox.so, bizid:16, so func:AfterSmu
[2018-01-18 04:05:40] NewSo path:../bin/bizso/biz_smartbox.so, bizid:16, so func:BuildResp
[2018-01-18 04:05:40] NewSo path:../bin/bizso/biz_smartbox.so, bizid:16, so func:SoInit
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitSo:256] Dynamic....getfunc...255:         SMARTBOX_PID:0  SMARTBOX_BID:16
[2018-01-18 04:05:40] NewSo path:../bin/libsmart_box.so, bizid:4509715661300, so func:Init
[2018-01-18 04:05:40] NewSo path:../bin/libsmart_box.so, bizid:4509715661300, so func:UnInit
[2018-01-18 04:05:40] file monitor successfully start
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitSo:265] Init smartbox success, smartbox will be enabled!
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:Init:151] Init all end...151
[2018-01-18 04:05:40] [ECHO] [adaptor_mcd_proc.cpp:Init:152]
-----------------config begin-------------------

[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:Init:153] cfg...153
[2018-01-18 04:05:40] CBusinessConfig...70[2018-01-18 04:05:40] File:common/kv_module/cache_ctrl_lock.cc,Line:47,Fuction:cache_init-->Creating cache[0] shm: key[0x009ae138], size[10 MB].
[2018-01-18 04:05:40] update file path: ./temp/new_file
[2018-01-18 04:05:40] File:common/kv_module/cache_ctrl_lock.cc,Line:173,Fuction:CacheLockInit-->Creating cache[0] lock: key[0x4c0509ab]
[2018-01-18 04:05:40] [ERROR]###### [busi_config.cpp:CheckInit:429] CheckInit nowbiznum:-1650, nowbizlen:-13200#####
[2018-01-18 04:05:40] CBusinessConfig...74[2018-01-18 04:05:40] [DEBUG] [http_timer_info.cpp:LoadHost2bizMap:930] LoadHost2bizMap...930
[2018-01-18 04:05:40] NewSo path:../bin/libsmart_box.so, bizid:4509715661300, so func:UnInit
[2018-01-18 04:05:40] file monitor successfully start
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:InitSo:265] Init smartbox success, smartbox will be enabled!
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:Init:151] Init all end...151
[2018-01-18 04:05:40] [ECHO] [adaptor_mcd_proc.cpp:Init:152]
-----------------config begin-------------------

[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:Init:153] cfg...153
[2018-01-18 04:05:40] CBusinessConfig...70[2018-01-18 04:05:40] File:common/kv_module/cache_ctrl_lock.cc,Line:47,Fuction:cache_init-->Creating cache[0] shm: key[0x009ae138], size[10 MB].
[2018-01-18 04:05:40] update file path: ./temp/new_file
[2018-01-18 04:05:40] File:common/kv_module/cache_ctrl_lock.cc,Line:173,Fuction:CacheLockInit-->Creating cache[0] lock: key[0x4c0509ab]
max_question_len:1000

[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:Init:153] cfg...153
[2018-01-18 04:05:40] CBusinessConfig...70[2018-01-18 04:05:40] File:common/kv_module/cache_ctrl_lock.cc,Line:47,Fuction:cache_init-->Creating cache[0] shm: key[0x009ae138], size[10 MB].
[2018-01-18 04:05:40] update file path: ./temp/new_file
[2018-01-18 04:05:40] File:common/kv_module/cache_ctrl_lock.cc,Line:173,Fuction:CacheLockInit-->Creating cache[0] lock: key[0x4c0509ab]
[2018-01-18 04:05:40] [ERROR]###### [busi_config.cpp:CheckInit:429] CheckInit nowbiznum:-1650, nowbizlen:-13200#####
[2018-01-18 04:05:40] CBusinessConfig...74[2018-01-18 04:05:40] [DEBUG] [http_timer_info.cpp:LoadHost2bizMap:930] LoadHost2bizMap...930
[2018-01-18 04:05:40] [DEBUG] [http_timer_info.cpp:LoadHost2bizMap:948] root.size()  :1
[2018-01-18 04:05:40] [DEBUG] [http_timer_info.cpp:LoadHost2bizMap:960] host:10.3.1.11:120
[2018-01-18 04:05:40] [DEBUG] [http_timer_info.cpp:LoadHost2bizMap:977] white_li:10.3.1.11
[2018-01-18 04:05:40] [DEBUG] [adaptor_mcd_proc.cpp:Init:165] m_cfg._parse_path:../bin/parse_biz.so
[2018-01-18 04:05:40] [ECHO] [http_timer_info.cpp:LoadFuncParse:1026] Load Parse biz function success.
[2018-01-18 04:05:40] adaptor server started.....
[2018-01-18 04:05:41] Inner message.
[2018-01-18 04:05:41] [Echo_ping] Receiver a new ping request.
[2018-01-18 04:05:41] [GetVersion] get version. key:[133956585_ver], ret:[-13200], datalen:[-13200], version:[0]
[2018-01-18 04:05:41] [SetNowBizList] ret:[0], len:[8]
[2018-01-18 04:05:41] PingList:[pid:2044,bid:1001,biz:133956585], delnum:[0]
[2018-01-18 04:05:41] [ECHO] [adaptor_mcd_proc.cpp:Enqueue_2_inner_ccd:970] [Enqueue_2_inner_ccd] enqueue to CCD success

[2018-01-18 04:05:41] Inner message.
[2018-01-18 04:05:41] [DEBUG] [adaptor_mcd_proc.cpp:Update_config:910] [Update_config] Receiver a new push config request.

[2018-01-18 04:05:41] [UpdateBusiConf] pid:[2044], bid:[1001], biz:[133956585] version:[303], conf:[{"relate_biz":[133960681],"muti_wheel":100,"kvs_addr":"10.3.1.11:54300","chat_history":1,"l5ranker_path":"../l5ranker/default","so_path":"../bin/bizso/biz_default.so","filt_docs":[3934],"auth":0,"private":{"docs":5}}]
[2018-01-18 04:05:41] [SetVersion] set version. key:[133956585_ver], ret:[0], version:[303]
[2018-01-18 04:05:41] [SetRbuAddr] set smu addr ip. key:[133956585_smu_ip0],
[2018-01-18 04:05:41] [SetRbuAddr] set smu addr port. key:[133956585_smu_port0],
[2018-01-18 04:05:41] UnLoadSo, pid:2044, bid:1001, bizid:8778913154025
[2018-01-18 04:05:41] _map_biz_func_name_ptr find...bizid:1001...174[2018-01-18 04:05:41] _map_biz_sopath find...bizid:1001...189[2018-01-18 04:05:41] bizid:1001
[2018-01-18 04:05:41] not find _map_path_bizso[2018-01-18 04:05:41] path:../bin/bizso/biz_default.so[2018-01-18 04:05:41] new_so_bizid...194[2018-01-18 04:05:42] NewSo path:../bin/bizso/biz_default.so, bizid:8778913154025, so func:InitRequest
[2018-01-18 04:05:42] NewSo path:../bin/bizso/biz_default.so, bizid:8778913154025, so func:BeforeSmu
[2018-01-18 04:05:42] NewSo path:../bin/bizso/biz_default.so, bizid:8778913154025, so func:AfterSmu
[2018-01-18 04:05:42] NewSo path:../bin/bizso/biz_default.so, bizid:8778913154025, so func:BuildResp
[2018-01-18 04:05:42] NewSo path:../bin/bizso/biz_default.so, bizid:8778913154025, so func:SoInit
[2018-01-18 04:05:42] pid:2044  bid:1001  func_name:SoInit[2018-01-18 04:05:42] GetFunc...278...bizid:1001[2018-01-18 04:05:42] _map_biz_func_name_ptr find...bizid[2018-01-18 04:05:42] mit->second...:?????^O^_[2018-01-18 04:05:42] [DEBUG] [busi_config.cpp:LoadSo:403] pid:2044, bid:1001, sopath:../bin/bizso/biz_default.so, LoadSo Succ
[2018-01-18 04:05:42] [SetConf]. key:[133956585_conf], ret:[0], conf:[{"relate_biz":[133960681],"muti_wheel":100,"kvs_addr":"10.3.1.11:54300","chat_history":1,"l5ranker_path":"../l5ranker/default","so_path":"../bin/bizso/biz_default.so","filt_docs":[3934],"auth":0,"private":{"docs":5}}]
[2018-01-18 04:05:42] [DelValue] Delete value in shm failed! key:[133956585_max_return_doc], ret:[-13200]
[2018-01-18 04:05:42] [DelValue] Delete value in shm failed! key:[133956585_channels], ret:[-13200]
[2018-01-18 04:05:42] [DelValue] Delete value in shm failed! key:[133956585_sensitive], ret:[-13200]
[2018-01-18 04:05:42] [DelValue] Delete value in shm failed! key:[133956585_emotion], ret:[-13200]
[2018-01-18 04:05:42] [DelValue] Delete value in shm failed! key:[133956585_biz_type], ret:[-13200]
[2018-01-18 04:05:42] [ECHO] [adaptor_mcd_proc.cpp:Enqueue_2_inner_ccd:970] [Enqueue_2_inner_ccd] enqueue to CCD success
	}