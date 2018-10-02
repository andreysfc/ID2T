#include "pcap_processor.h"
#include <pybind11/pybind11.h>
#include <pybind11/embed.h>

namespace py = pybind11;

int main(){
    // pcap/2min.dump, True, /home/pepper-jk/code/ID2T-toolkit/code/ID2TLib/../../resources/, /home/pepper-jk/.cache/id2t/db/73/45/dbdec9ab5040.sqlite3
    std::string pcap_path = "pcap/2min.dump";
    std::string extra_tests = "True";
    std::string resource_path = "/home/pepper-jk/code/ID2T-toolkit/code/ID2TLib/../../resources/";
    std::string db_path = "/home/pepper-jk/.cache/id2t/db/73/45/dbdec9ab5040.sqlite3";

    std::cout << "start" << std::endl;

    py::scoped_interpreter guard{};
    std::cout << "interpreter" << std::endl;
    pcap_processor pp(pcap_path, extra_tests, resource_path, db_path);
    std::cout << "pp" << std::endl;

    // [10.0]
    py::list intervals;
    std::cout << "py::list" << std::endl;
    py::float_ elem = 10.0;
    intervals.append(elem);
    std::cout << "py::list" << std::endl;

    pp.collect_statistics(intervals);
    std::cout << "collect_statistics" << std::endl;

    // /home/pepper-jk/.cache/id2t/db/73/45/dbdec9ab5040.sqlite3, [10.0], True
    bool del = true;

    pp.write_to_database(db_path, intervals, del);
    std::cout << "write_to_database" << std::endl;

    return 0;
}
