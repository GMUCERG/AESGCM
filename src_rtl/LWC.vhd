-------------------------------------------------------------------------------
--! @file       AEAD.vhd
--! @brief      Entity and architecture of authenticated encryption unit.
--!             Note: This file should not be modified by a user.
--! @project    CAESAR Candidate Evaluation
--! @author     Ekawat (ice) Homsirikamol
--!             Kamyar Mohajerani: Ported to NIST LWC API and VHDL fixes
--! @copyright  Copyright (c) 2016 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             —unrestricted)
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use work.AEAD_pkg.all;
use work.NIST_LWAPI_pkg.all;

entity LWC is
    port (
        --! Global ports
        clk             : in  std_logic;
        rst             : in  std_logic;
        --! Publica data ports
        pdi_data        : in  std_logic_vector(W-1 downto 0);
        pdi_valid       : in  std_logic;
        pdi_ready       : out std_logic;
        --! Secret data ports
        sdi_data        : in  std_logic_vector(SW-1 downto 0);
        sdi_valid       : in  std_logic;
        sdi_ready       : out std_logic;
        --! Data out ports
        do_data         : out std_logic_vector(W-1 downto 0);
        do_last         : out std_logic;
        do_ready        : in  std_logic;
        do_valid        : out std_logic
    );
end entity;

-------------------------------------------------------------------------------
--! @brief  Architecture definition of LWC
-------------------------------------------------------------------------------
architecture structure of LWC is
    --! Special features parameters
    constant G_ENABLE_PAD    : boolean := False; --! Enable padding
    constant G_CIPH_EXP      : boolean := False; --! Ciphertext expansion
    constant G_REVERSE_CIPH  : boolean := False; --! Reversed ciphertext
    constant G_MERGE_TAG     : boolean := False; --! Merge tag with data segment
    --! Block size (bits)
    constant G_ABLK_SIZE     : integer := 128;   --! Associated data
    constant G_DBLK_SIZE     : integer := 128;   --! Data
    constant G_KEY_SIZE      : integer := 32;    --! Key
    constant G_TAG_SIZE      : integer := 128;   --! Tag
    --! Padding options
    constant G_PAD_STYLE     : integer := 0;     --! Pad style
    constant G_PAD_AD        : integer := 1;     --! Padding behavior for AD
    constant G_PAD_D         : integer := 1;     --! Padding behavior for Data
    --! Maximum supported AD/message/ciphertext length = 2^G_MAX_LEN-1
    constant G_MAX_LEN       : integer := SINGLE_PASS_MAX;

    constant LBS_BYTES      : integer   := log2_ceil(G_DBLK_SIZE/8);
    --! Signals from input processor
    signal key              : std_logic_vector(G_KEY_SIZE -1 downto 0);
    signal bdi              : std_logic_vector(G_DBLK_SIZE-1 downto 0);

    signal key_valid        : std_logic;
    signal key_ready        : std_logic;    
    signal key_update       : std_logic;
    signal decrypt          : std_logic;
    signal bdi_valid        : std_logic;
    signal bdi_ready        : std_logic;
    signal bdi_partial      : std_logic;
    signal bdi_eot          : std_logic;
    signal bdi_eoi          : std_logic;
    signal bdi_type         : std_logic_vector(3            -1 downto 0);
    signal bdi_size         : std_logic_vector(LBS_BYTES+1  -1 downto 0);
    signal bdi_valid_bytes  : std_logic_vector(G_DBLK_SIZE/8-1 downto 0);
    signal bdi_pad_loc      : std_logic_vector(G_DBLK_SIZE/8-1 downto 0);

    --! Signals to output processor
    signal bdo_ready        : std_logic;
    signal bdo_valid        : std_logic;
    signal bdo              : std_logic_vector(G_DBLK_SIZE-1 downto 0);
    signal bdo_size         : std_logic_vector(LBS_BYTES+1-1 downto 0);
    signal msg_auth_done    : std_logic;
    signal msg_auth_valid   : std_logic;

    --! FIFO
    signal cmd_din          : std_logic_vector(24-1 downto 0);
    signal cmd_dout         : std_logic_vector(24-1 downto 0);
    signal cmd_rd_ready     : std_logic;
    signal cmd_wr_ready     : std_logic;
    signal cmd_wr_valid     : std_logic;
    signal cmd_rd_valid     : std_logic;
begin

    u_input: entity work.PreProcessor(structure)
    generic map (
        G_W                 => W              ,
        G_SW                => SW             ,
        G_ASYNC_RSTN        => ASYNC_RSTN     ,
        G_ENABLE_PAD        => G_ENABLE_PAD     ,
        G_CIPH_EXP          => G_CIPH_EXP       ,
        G_REVERSE_CIPH      => G_REVERSE_CIPH   ,
        G_MERGE_TAG         => G_MERGE_TAG      ,
        G_ABLK_SIZE         => G_ABLK_SIZE      ,
        G_DBLK_SIZE         => G_DBLK_SIZE      ,
        G_KEY_SIZE          => G_KEY_SIZE       ,
        G_LBS_BYTES         => LBS_BYTES        ,
        G_PAD_STYLE         => G_PAD_STYLE      ,
        G_PAD_AD            => G_PAD_AD         ,
        G_PAD_D             => G_PAD_D
    )
    port map (
        --! Global
        clk                 => clk              ,
        rst                 => rst              ,
        --! External
        pdi_data            => pdi_data         ,
        pdi_valid           => pdi_valid        ,
        pdi_ready           => pdi_ready        ,
        sdi_data            => sdi_data         ,
        sdi_valid           => sdi_valid        ,
        sdi_ready           => sdi_ready        ,
        --! CipherCore (Data)
        bdi                 => bdi              ,
        key                 => key              ,
        --! CipherCore (Control)
        key_valid           => key_valid        ,
        key_ready           => key_ready        ,
        key_update          => key_update       ,
        decrypt             => decrypt          ,
        bdi_ready           => bdi_ready        ,
        bdi_valid           => bdi_valid        ,
        bdi_type            => bdi_type         ,
        bdi_partial         => bdi_partial      ,
        bdi_eot             => bdi_eot          ,
        bdi_eoi             => bdi_eoi          ,
        bdi_size            => bdi_size         ,
        bdi_valid_bytes     => bdi_valid_bytes  ,
        bdi_pad_loc         => bdi_pad_loc      ,
        --! cmd FIFO
        cmd                 => cmd_din          ,
        cmd_ready           => cmd_wr_ready     ,
        cmd_valid           => cmd_wr_valid
    );

    u_cc:
    entity work.CipherCore(structure)
    generic map (
        G_ASYNC_RSTN        => ASYNC_RSTN     ,
        G_DBLK_SIZE         => G_DBLK_SIZE      ,
        G_KEY_SIZE          => G_KEY_SIZE       ,
        G_TAG_SIZE          => G_TAG_SIZE       ,
        G_LBS_BYTES         => LBS_BYTES        ,
        G_MAX_LEN           => G_MAX_LEN
    )
    port map (
        --! Global
        clk                 => clk              ,
        rst                 => rst              ,
        --! PreProcessor (data)
        key                 => key              ,
        bdi                 => bdi              ,
        --! PreProcessor (controls)
        key_valid           => key_valid        ,
        key_ready           => key_ready        ,        
        key_update          => key_update       ,
        decrypt             => decrypt          ,
        bdi_ready           => bdi_ready        ,
        bdi_valid           => bdi_valid        ,
        bdi_type            => bdi_type         ,
        bdi_partial         => bdi_partial      ,
        bdi_eot             => bdi_eot          ,
        bdi_eoi             => bdi_eoi          ,
        bdi_size            => bdi_size         ,
        bdi_valid_bytes     => bdi_valid_bytes  ,
        bdi_pad_loc         => bdi_pad_loc      ,
        --! PostProcessor
        bdo                 => bdo              ,
        bdo_ready           => bdo_ready        ,
        bdo_valid           => bdo_valid        ,
        bdo_size            => bdo_size         ,
        msg_auth_valid      => msg_auth_valid   ,
        msg_auth_done       => msg_auth_done
    );

    u_output:
    entity work.PostProcessor(structure)
    generic map (
        G_W                 => W                ,
        G_SW                => SW               ,
        G_ASYNC_RSTN        => ASYNC_RSTN       ,        
        G_CIPH_EXP          => G_CIPH_EXP       ,
        G_REVERSE_CIPH      => G_REVERSE_CIPH   ,
        G_MERGE_TAG         => G_MERGE_TAG      ,
        G_LBS_BYTES         => LBS_BYTES        ,
        G_DBLK_SIZE         => G_DBLK_SIZE      ,
        G_TAG_SIZE          => G_TAG_SIZE
    )
    port map (
        --! Global
        clk                 => clk              ,
        rst                 => rst              ,
        --! External
        do_data             => do_data          ,
        do_last             => do_last          ,
        do_ready            => do_ready         ,
        do_valid            => do_valid         ,
        --! CipherCore
        bdo_ready           => bdo_ready        ,
        bdo_valid           => bdo_valid        ,
        bdo                 => bdo              ,
        bdo_size            => bdo_size         ,
        msg_auth_valid      => msg_auth_valid   ,
        msg_auth_done       => msg_auth_done    ,
        --! cmd FIFOs
        cmd                 => cmd_dout         ,
        cmd_ready           => cmd_rd_ready     ,
        cmd_valid           => cmd_rd_valid
    );

    u_hdr_buffer:
    entity work.fwft_fifo(structure)
    generic map (
        G_W                 => 24               ,
        G_LOG2DEPTH         => 2                ,
        G_ASYNC_RSTN        => ASYNC_RSTN
    )
    port map (
        clk                 => clk              ,
        rst                 => rst              ,
        din                 => cmd_din          ,        
        din_valid           => cmd_wr_valid     ,
        din_ready           => cmd_wr_ready     ,
        dout                => cmd_dout         ,
        dout_valid          => cmd_rd_valid     ,
        dout_ready          => cmd_rd_ready
    );
end structure;