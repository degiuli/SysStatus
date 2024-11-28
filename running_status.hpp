/*--
The MIT License (MIT)

Copyright (c) 2010-2019 De Giuli Informática Ltda. (http://www.degiuli.com.br)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
--*/

#pragma once

#include <atomic>

class running_status
{
    std::atomic_bool terminate_{ false };
    std::atomic_bool shutdown_{ false };
    std::atomic_bool force_checking_{ false };

public:
    running_status(running_status const&) = delete;
    running_status& running_status::operator=(running_status const&) = delete;
    running_status(running_status const&&) = delete;
    running_status&& running_status::operator=(running_status const&&) = delete;

    void set_terminate(bool const flag)
    {
        terminate_.store(flag, std::memory_order_seq_cst);
    }
    bool get_shutdown()
    {
        return shutdown_.load(std::memory_order_seq_cst);
    }

    void set_shutdown(bool const flag)
    {
        shutdown_.store(flag, std::memory_order_seq_cst);
    }
    bool get_shutdown()
    {
        return shutdown_.load(std::memory_order_seq_cst);
    }

    void set_force_checking(bool const flag)
    {
        force_checking_.store(flag, std::memory_order_seq_cst);
    }
    bool get_force_checking()
    {
        return force_checking_.load(std::memory_order_seq_cst);
    }
};
