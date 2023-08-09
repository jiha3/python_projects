import angr
import sys
import os

def load_trace(trace_log):
    trace = []
    with open(trace_log, 'rb') as fr:
        for line in fr:
            addr, opcode = line.rstrip().split(',')
            trace.append({"address":addr, "opcode":opcode})
    return trace

def dynamic_call_sequence(func_list, trace):
    sequence = []
    ##### For Students
    ##### fill this function to return the call sequence
    ##### using the instruction trace of executed malware
    #####
    temp_trace = trace
    mine_count = {}
    targets = []
    while(len(temp_trace)>0):
        for i, temp in enumerate(temp_trace):
            temp_adr = temp['address']
            targets.append(temp['address'])
            if temp_adr in targets[:-1]:
                before_index = targets.index(temp_adr)
                diff = i-before_index
                if targets[i-1] == targets[i+diff-1]:
                    mine = [targets[k] for k in (before_index, i-1)]
                    if mine in mine_count.keys():
                        count = mine_count[mine]
                        mine_count.update({mine:count+1})
                    else:
                        mine_count.update({mine:1})
                temp_trace = temp_trace[i+diff:]
                break
    return mine_count


def find_loop(sequence):
    loop_sequence = []
    ### For Students
    ### Find the functions repetead in the loop
    ### The malware tries to communicate with C&C server
    ### Since the communication is forbidden, 
    ### malware keep trying to establish a connection
    ###
    return loop_sequence



def main():

    binary_path = sys.argv[1]
    if not os.path.exists(binary_path):
      print("Error: binary does not exist at %s" % binary_path)
      quit()
      
    proj = angr.Project(binary_path,
    use_sim_procedures=True,
    default_analysis_mode='symbolic',
    load_options={'auto_load_libs': False})

    proj.hook_symbol('lstrlenA', angr.SIM_PROCEDURES['libc']['strlen'])
    proj.hook_symbol('StrCmpNIA', angr.SIM_PROCEDURES['libc']['strncmp'])

    r2cfg = proj.analyses.Radare2CFGRecover()
    r2cfg._analyze(binary_path)

    flist = r2cfg.function_list()

    trace = load_trace('./instrace.linux.log')
    sequence = dynamic_call_sequence(flist, trace)

    #loop = find_loop(sequence)
    #print loop
    print(sequence)



if __name__ == "__main__":

  if(len(sys.argv) != 2):
    print("Usage: %s [target-program] " \
             % sys.argv[0])
    quit()
  main()
