#include <hexrays.hpp>
#include <frame.hpp>
#include <nalt.hpp>

#include <optional>

static ssize_t idaapi cb_handler(void *ud, hexrays_event_t event, va_list va);

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
	~plugin_ctx_t()
	{
		uninstall_cb();
		term_hexrays_plugin();
	}
	virtual bool idaapi run(size_t) override;
	void install_cb();
	void uninstall_cb();
	
	bool registered_cb = false;
};

struct call_t {
	cexpr_t *call;
	int funcexpr_ctidx = -1;
	cexpr_t *callobj;
	int func_ctidx = -1;
	cexpr_t *first_arg;
	int farg_ctidx = -1;
	carg_t *second_arg;
	int second_arg_ctidx = -1;
};

using citempos_t = std::tuple<size_t, size_t>;

static qstring make_ctag(char c0, char c1) {
	char tag[2];
	tag[0] = c0;
	tag[1] = c1;
	return qstring(tag, 2);
}

static qstring make_ctag_str(char color, qstring str) {
	return make_ctag(COLOR_ON, color) + str + make_ctag(COLOR_OFF, color);
}

static qstring make_ctag_str(char color, const char *str) {
	return make_ctag(COLOR_ON, color) + str + make_ctag(COLOR_OFF, color);
}

static qstring make_addrtag() {
	char funcpattern[2];
	funcpattern[0] = COLOR_ON;
	funcpattern[1] = COLOR_ADDR;
	return qstring(funcpattern, 2);
}

static qstring make_addr(int index) {
	char funcpattern[2 + 16 + 1];
	funcpattern[0] = COLOR_ON;
	funcpattern[1] = COLOR_ADDR;
	qsnprintf(&funcpattern[2], 17, "%016X", index);
	return qstring(funcpattern, sizeof(funcpattern) - 1);
}

static int callback(cfunc_t *func) {
	struct call_finder_t : public ctree_visitor_t
	{
	public:
		call_finder_t() : ctree_visitor_t(CV_FAST) {}
		
		qvector<call_t> nonvirtual_calls;
		
		qvector<call_t> export_nonvirtual_calls() {
			return std::move(nonvirtual_calls);
		}
		
		int idaapi visit_expr(cexpr_t *expr) override {
			if (expr->op != cot_call)
				return 0;
			
			cexpr_t *callobj = expr->x;
			carglist_t *args = expr->a;
			
			if (callobj->op == cot_obj) {
				
				call_t call;
				call.call = expr;
				call.callobj = callobj;
				call.first_arg = args->size() ? &args->at(0) : nullptr;
				call.second_arg = args->size() >= 2 ? &args->at(1) : nullptr;
				
				nonvirtual_calls.push_back(call);
			} else if (callobj->op == cot_memref || callobj->op == cot_memptr) {
				//if (!args->size())
				//	return 0;
				//
				//tinfo_t farg_type = args->at(0).type;
				//std::optional<tinfo_t> sarg_type = args->size() >= 2 ? args->at(1).type : std::nullopt_t;
				//qstring a;
				//msg("call op @ %08X could be a vcall.\n", expr->ea);
				//callobj->type.print(&a);
				//// callobj->type = funcptr type inside vtable
				//// callobj->m    = offset in vtable
				//msg("m: 0x%X\n", callobj->m);
				//msg("callobj type: '%s'\n", a.c_str());
				//a.clear();
				//msg("fflags: '%d'\n", args->flags);
			}

			return 0;
		}
	};
	
	call_finder_t finder;
	
	finder.apply_to(&func->body, NULL);
	qvector<call_t> nonvirtual_calls = finder.export_nonvirtual_calls();
	
	if (!nonvirtual_calls.size()) return 0;
	
	/*
     * for non multiline: 
     * 1. func ctree, func name, funcexpr ctree, funcexpr "(", farg ctree, farg label, [either ) or ,]
     * builds:
     * funcname(farg)     OR  funcname(farg, ...)
     * turned into:
     * farg->funcname()   OR  farg->funcname(...)
     *
     * for multiline:
     * 1. func ctree, func name, funcexpr ctree, funcexpr "(", funcexpr ctree
     *    (func and funcexpr are on a single line)
     * 2. left multi space indent, farg ctree, farg label, comma, weird ctree ref, funcexpr ctree
          (farg is on the next line)
     * builds:
     * func(
     *     [farg,]
     * turned into:
     * farg->func(
     *     (other stuff)
     * multiline should be easier to handle; we can be deterministic about a lot of things
	 */
	
	for (auto& call : nonvirtual_calls) {
		call.funcexpr_ctidx = func->treeitems.index(call.call);
		call.func_ctidx = func->treeitems.index(call.callobj);
		if (call.first_arg)
			call.farg_ctidx = func->treeitems.index(call.first_arg);
		if (call.second_arg)
			call.second_arg_ctidx = func->treeitems.index(call.second_arg);
		//msg("found call to %08X @ %08X %s first arg, %s last arg, idxs: %X funcexpr, %X func, %X farg, %X sarg\n",
		//	call.callobj->obj_ea,
		//	call.call->ea,
		//	call.first_arg ? "with" : "without",
		//	call.second_arg ? "with" : "without",
		//	call.funcexpr_ctidx,
		//	call.func_ctidx,
		//	call.farg_ctidx,
		//	call.second_arg_ctidx);
	}
	
	//for (auto& ui : func->sv) {
	//	auto& l = ui.line;
	//	//msg("%s\n", l.c_str());
	//	for (int i = 0; i < l.length(); i++) {
	//		msg("%02X", l[i]);
	//	}
	//	msg("%02X", 0xA);
	//}
	//msg("\n");
	
	// just do the last call for now
	for (auto &lc : nonvirtual_calls)
	{
		if (!lc.first_arg && !lc.second_arg)
		{
			// if it's not a call involving an object, we exit
			continue;
		}
	
		for (size_t lineidx = 0; lineidx < func->sv.size(); lineidx++)
		{
			auto& curline = func->sv[lineidx].line;
			qstring *nextline = &curline;
			
			const qstring func_ctreeaddr = make_addr(lc.func_ctidx);
			const qstring farg_ctreeaddr = make_addr(lc.farg_ctidx);
			const qstring funcexpr_ctreeaddr = make_addr(lc.funcexpr_ctidx);
			
			// points to address tag of call expression beginning
			size_t funcexpr_start = curline.find(funcexpr_ctreeaddr);
			// points to address tag of function
			size_t func_start = curline.find(func_ctreeaddr);
			// points to address tag of final component of first argument
			// NOTE: points to nl if is_multiline
			size_t farg_start = curline.find(farg_ctreeaddr);
			
			bool is_multiline = false;
			
			/* in all cases, it is mandatory for funcexpr & func to be on one line */
			if (funcexpr_start == qstring::npos || func_start == qstring::npos)
				continue;
			
			/* farg on the other hand can be on the next line as part of a multi line printed funcexpr */
			if (farg_start == qstring::npos) {
				/* but if we're out of lines to look in, exit */
				if (lineidx - 1 > func->sv.size() + 1)
					break;
				
				/* otherwise farg_start points to lineidx + 1 (!) */
				nextline = &func->sv[lineidx + 1].line;
				farg_start = nextline->find(farg_ctreeaddr);
				if (farg_start != qstring::npos) {
					is_multiline = true;
					//msg("found multiline funcexpr\n");
				}
			}
			
		// -- begin area that doesn't care about multiline --
			
			// points to color start tag of function
			size_t funcname_begin_color_tag = func_start + func_ctreeaddr.length();
			// points to start of function name
			size_t funcname_start = funcname_begin_color_tag + 2;
			// points to end of function name / start of end color tag
			size_t funcname_end = curline.find(make_ctag(COLOR_OFF, COLOR_DEMNAME), funcname_start);
			// full function name, should be namespaces::class::function
			qstring full_funcname = curline.substr(funcname_start, funcname_end);
			
			qvector<qstring> splits;
			full_funcname.split(&splits, "::");
			
			// function part of namespaces::class::function
			qstring actual_funcname = full_funcname;
			
			if (splits.size() >= 2) {
				actual_funcname = splits[splits.size() - 1];
			} else {
				// function name is not in the expected format, we exit
				break;
			}
			
			// get the namespaces::class part
			splits.pop_back();
			qstring wanted_farg_type = qstring::join(splits, "::");
			
			tinfo_t actual_farg_type = lc.first_arg->type;
			if (actual_farg_type.is_ptr()) {
				ptr_type_data_t ptrtypedata;
				actual_farg_type.get_ptr_details(&ptrtypedata);
				if (ptrtypedata.obj_type.is_ptr()) {
					// no support for double pointers.
					break;
				}
				actual_farg_type = ptrtypedata.obj_type;
			}
			
			qstring actual_farg_type_str;
			actual_farg_type.print(&actual_farg_type_str);
			
			// it is possible that the pointer type we're passing (aka actual_farg_type)
			// is a derivative class of the wanted class.
			// meaning we need to know what base classes there are for it
			bool farg_type_is_matching_derivative = false;
			if (actual_farg_type.is_cpp_struct()) {
				// requirement is __cppobj because only those can be derivatives
				udt_type_data_t udt_typedata;
				actual_farg_type.get_udt_details(&udt_typedata);
				for (auto &udt : udt_typedata) {
					if (udt.is_baseclass()) {
						qstring t;
						udt.type.print(&t);
						if (t == wanted_farg_type) {
							farg_type_is_matching_derivative = true;
							break;
						}
					}
				}
			}
			
			if (actual_farg_type_str != wanted_farg_type && !farg_type_is_matching_derivative) {
				// type matches neither directly nor indirectly (through a baseclass).
				// we exit.
				break;
			}
					
		// -- end area that doesn't care about multiline --

			if (!is_multiline) {
				// if `this` is obj->x->y...
				// lc.first_arg would point to `y`
				// we need to go back.
				farg_start = funcexpr_start + funcexpr_ctreeaddr.length() + make_ctag_str(COLOR_SYMBOL, "(").length();
			} else {
				// for multiline, we can just find the first addr tag
				farg_start = nextline->find(make_addrtag()) - 1;
			}
			
			qstring& farg_line = is_multiline ? *nextline : curline;

			// contains the (type) part of (type)var, and a deref operator (*) if applicable
			qstring prefix_expr = "";
			
			// contains a [0] for cases where a function is called on the first element of an array
			qstring suffix_expr = "";
			
			bool force_obj = false;
			
			if (lc.first_arg->op == cot_ptr) { // *x
				ptr_type_data_t deref_type;
				lc.first_arg->type.get_ptr_details(&deref_type);
				if (!deref_type.obj_type.is_ptr()) {
					force_obj = true;
				}
				const qstring deref_part = farg_ctreeaddr + make_ctag_str(COLOR_SYMBOL, "*");
				if (farg_line.find(deref_part, farg_start) != farg_start) {
					info("%08X: could not decode pointer deref expression\n", lc.call->ea);
					break;
				}
				
				prefix_expr += farg_line.substr(farg_start, farg_start + deref_part.length());
				farg_start += deref_part.length();
				lc.first_arg = lc.first_arg->x;
			}
			
			// if farg is a cast, we need to undo the cast, and grab the cast expression
			if (lc.first_arg->op == cot_cast)
			{
				const qstring visible_cast_begin = make_ctag_str(COLOR_SYMBOL, "(") + make_ctag(COLOR_ON, COLOR_HIDNAME);
				const qstring visible_cast_end = make_ctag(COLOR_OFF, COLOR_HIDNAME) + make_ctag_str(COLOR_SYMBOL, ")");
				
				// grab the ctree addr of the cast first
				qstring cast_expr = farg_line.substr(farg_start, farg_start + farg_ctreeaddr.length());
				
				size_t visible_cast_startidx = farg_start + farg_ctreeaddr.length();
				
				// the user might disable casts, in which case the visible (type) part of (type)var is not shown
				// if it is visible, we need to include the (type) in the cast expression for later
				if (farg_line.find(visible_cast_begin, visible_cast_startidx) == visible_cast_startidx) {
					// so we show (type)var->Func(...)
					size_t cast_endidx = farg_line.find(visible_cast_end, visible_cast_startidx) + visible_cast_end.length();
					cast_expr += farg_line.substr(visible_cast_startidx, cast_endidx);
				}
				
				// advance farg to the var part of (type)var
				farg_start += cast_expr.length();
				prefix_expr += cast_expr;
			}
			
			// NOTE: not for multiline
			qstring arg_sep = "";
			// NOTE: not for multiline
			size_t post_farg = 0;
			
			size_t farg_end = 0;
			
			if (!is_multiline) {
				// for single-line calls, the end of farg is either:
				// - the comma for the next arg; OR
				// - the ending parenthesis of the function call

				arg_sep =
					lc.second_arg ?
						make_ctag_str(COLOR_SYMBOL, ",") + " " /* look for ", " when there is at least a second arg */
						:
						make_ctag_str(COLOR_SYMBOL, ")") /* otherwise just look for the ending parenthesis */;
	
				farg_end = farg_line.find(arg_sep, farg_start);
				
				if (!lc.second_arg && farg_line.find("ADJ", farg_start) != qstring::npos) {
					// because ADJ has its own closing parenthesis,
					// we need to skip that to find the ending parenthesis
					// in order to get to the end of the first argument
					farg_end = farg_line.find(arg_sep, farg_end + arg_sep.length());
				}
				post_farg = farg_end + arg_sep.length();
			} else {
				// for multiline calls, the end of farg is just the end of the farg line
				farg_end = nextline->size() - 1;
			}

			qstring farg = farg_line.substr(farg_start, farg_end);
			
			if (is_multiline) {
				// NOTE: we need to remove the last comma since farg would include that here
				const qstring comma = make_ctag_str(COLOR_SYMBOL, ",") + make_addrtag();
				size_t comma_idx = farg.find(comma);
				farg.remove(comma_idx, comma_idx + comma_idx + comma.length() - 2);
			}
			
		// -- begin area that doesn't care about multiline 2 --
			
			const qstring pointer_and_part    = make_ctag_str(COLOR_SYMBOL, "&");
			const qstring farg_removable_part = farg_ctreeaddr + pointer_and_part;
				
			if (!force_obj) {
				// `this` is in the format &expr
				if (lc.first_arg->op == cot_obj) {
					tinfo_t obj_type;
					get_tinfo(&obj_type, lc.first_arg->obj_ea);
					if (obj_type.is_array()) {
						array_type_data_t array_tdata;
						obj_type.get_array_details(&array_tdata);
						force_obj = !array_tdata.elem_type.is_ptr();
						suffix_expr += make_ctag_str(COLOR_SYMBOL, "[") + make_ctag_str(COLOR_KEYWORD, "0") + make_ctag_str(COLOR_SYMBOL, "]");
					}
				}
				else if (lc.first_arg->op == cot_ref) {
					// the expr part of &expr
					cexpr_t *referenced_farg = lc.first_arg->x;
					int referenced_cart_ctindex = func->treeitems.index(referenced_farg);
						
					if (referenced_cart_ctindex != -1) {
						const qstring force_obj_cond = 
							farg_removable_part +
							make_addr(referenced_cart_ctindex);
							
						// if it actually references the expr, it's not a pointer
						// force it to be treated as such
						force_obj = farg.find(force_obj_cond) != qstring::npos;
					}
					
					if (referenced_farg->op == cot_memptr) {
						force_obj = true;
					}					
					
					if (referenced_farg->op == cot_memref) {
						force_obj = true;
					}					
					
					if (referenced_farg->op == cot_idx) {
						force_obj = true;
					}					
					
					if (force_obj) {
						// if we treat it as not a pointer, we need
						// to remove the & part of &expr
						// so that we use expr.Function(...) instead of &expr.Function()
						farg = farg.substr(farg_removable_part.length());
					}
				}
			}
			
			// determine which call operator to use depending on what the call item is
			qstring call_operator = "";
			if (!lc.first_arg->type.is_ptr() || force_obj) {
				call_operator = make_ctag_str(COLOR_SYMBOL, ".");
			} else {
				call_operator = make_ctag_str(COLOR_SYMBOL, "->");
			}
			
		// -- end area that doesn't care about multiline 2 --
		
			qstring final_farg = prefix_expr + farg + suffix_expr;
		    if (prefix_expr.length()) {
				final_farg = make_ctag_str(COLOR_SYMBOL, "(") + final_farg + make_ctag_str(COLOR_SYMBOL, ")");
			}
			
			if (!is_multiline) {
				qstring begin_until_func_start = curline.substr(0, func_start);
				qstring post_farg_part = curline.substr(post_farg);
				
				curline = 
					begin_until_func_start +
					final_farg +
					call_operator +
					make_addr(lc.func_ctidx) +
					make_ctag_str(COLOR_DEMNAME, actual_funcname) +
					make_ctag_str(COLOR_SYMBOL, "(") +
					(lc.second_arg ? "" : arg_sep) +
					post_farg_part;
			} else {
				// the idea is
				// before:          after:
				// 1. func(         1. [deleted]   1 = curline
				// 2.     farg      2. farg.func(  2 = nextline
				
				qstring begin_until_func = curline.substr(0, func_start); // indentation [    ]func(
				
				(*nextline) =
					begin_until_func +
					final_farg +
					call_operator +
					make_addr(lc.func_ctidx) +
					make_ctag_str(COLOR_DEMNAME, actual_funcname) +
					make_ctag_str(COLOR_SYMBOL, "(") +
					make_addr(lc.func_ctidx);
					
				func->sv.erase(&func->sv.at(lineidx));
				
				// iterating after this is NOT safe, exit
				break;
			}
		}
	}
	
	return 0;
}

static ssize_t idaapi cb_handler(void *ud, hexrays_event_t event, va_list va) {
	(void)ud;
	switch (event) {
		case hxe_func_printed: {
			cfunc_t *func = va_arg(va, cfunc_t *);
			return callback(func);
		}
		default:
		return 0;
	}
}

//--------------------------------------------------------------------------
void plugin_ctx_t::install_cb() {
	if (!registered_cb) {
		if (install_hexrays_callback(cb_handler, NULL)) {
			this->registered_cb = true;
		}
	}
}

void plugin_ctx_t::uninstall_cb() {
	if (registered_cb) {
		remove_hexrays_callback(cb_handler, NULL);
		this->registered_cb = false;
	}
}
static bool first_run = true;
bool idaapi plugin_ctx_t::run(size_t)
{
	if (first_run) {
		first_run = false;
		install_cb();
		return true;
	}
	
	bool had_enabled = registered_cb;
	if (registered_cb)
		uninstall_cb();
	else
		install_cb();
	
	info("C++ Reformatter is now %s.", had_enabled ? "disabled" : "enabled");
	
	return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
	if ( !init_hexrays_plugin() )
		return nullptr; // no decompiler
	plugin_ctx_t *plug = new plugin_ctx_t;
	plug->run(0);
	return plug;
}

//--------------------------------------------------------------------------
static const char comment[] = "C++ function call reformatter";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI | PLUGIN_PROC,
	init,                                     // initialize
	nullptr,
	nullptr,
	comment,                                  // long comment about the plugin
	nullptr,                                  // multiline help about the plugin
	"C++ function call reformatter",          // the preferred short name of the plugin
	nullptr,                                  // the preferred hotkey to run the plugin
};
